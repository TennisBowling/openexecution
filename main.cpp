#include <cpr/cpr.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <leveldb/db.h>
#include <leveldb/cache.h>
#include <leveldb/write_batch.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <format>
#include <crow.h>
#include "util.hpp"
#include "crow_log.hpp"
#include "rust_jwt/rust_jwt.hpp"
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <random>
using json = nlohmann::json;

leveldb::DB *db;

void signal_handler(int signal)
{
    spdlog::info("Caught signal {}, closing databases.", signal);
    delete db;
    spdlog::info("Database closed.");
    exit(signal);
}

cpr::Bearer create_bearer_jwt(std::string &token)
{
    const int64_t timestamp = static_cast<int64_t>(std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count());

    std::string jwt = make_jwt(token.data(), &timestamp);
    return cpr::Bearer{jwt};
}

// we let the operator of this program decide if they want to override the client's fee recipient address to their own
std::string make_fee_recipient(std::string originaladdress, double &chance, std::string &overrideaddress)
{
    // chance is a decimal representing the chance that the fee recipient will be overridden
    // 0.5 means 50% chance, 0.1 means 10% chance, etc.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0, 1);
    double random = dis(gen);
    if (random < chance)
    {
        return overrideaddress;
    }
    else
    {
        return originaladdress;
    }
}

int main(int argc, char *argv[])
{
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] - %v"); // nice style that i like

    auto vm = parse_args(argc, argv);

    int port;
    if (vm.count("port") == 0)
    {
        port = 8000;
    }
    else
    {
        port = vm["port"].as<int>();
    }

    std::string listenaddr;
    if (vm.count("listen-addr") == 0)
    {
        listenaddr = std::string("0.0.0.0");
    }
    else
    {
        listenaddr = vm["listen-addr"].as<std::string>();
    }

    double fee_override_chance;
    if (vm.count("fee-override-chance") == 0)
    {
        fee_override_chance = 0.0;
    }
    else
    {
        fee_override_chance = vm["fee-override-chance"].as<double>();
        spdlog::info("Fee override chance set to {}.", fee_override_chance);
    }

    std::string fee_override_address;
    if (vm.count("fee-override-address") == 0)
    {
        fee_override_address = std::string("");
    }
    else
    {
        fee_override_address = vm["fee-override-address"].as<std::string>();
        spdlog::info("Fee override address: {}", fee_override_address);
    }

    cpr::Url node{vm["node"].as<std::string>()};
    cpr::Url unauth_node{vm["unauth-node"].as<std::string>()};

    auto jwt = read_jwt(vm["jwt-secret"].as<std::string>());

    // setup leveldb
    leveldb::Options options;
    options.create_if_missing = true;
    options.block_cache = leveldb::NewLRUCache(3145728); // 3MB cache
    leveldb::Status status = leveldb::DB::Open(options, "./db", &db);
    if (!status.ok())
    {
        spdlog::error("Failed to open leveldb: {}", status.ToString());
        return 1;
    }

    // setup threadpool
    boost::asio::thread_pool pool(std::thread::hardware_concurrency());
    boost::asio::post(pool, [&]()
                      { spdlog::info("Starting threadpool with {} threads", std::thread::hardware_concurrency()); });

    // setup crow
    SpdLogAdapter adapter; // from crow_log.hpp
    crow::logger::setHandler(&adapter);
    crow::SimpleApp app;
    app.loglevel(crow::LogLevel::Warning);

    // setup signal handler
    app.signal_clear();
    signal(SIGINT, signal_handler);
    spdlog::debug("Signal handler set.");

    // last legitamate fcU (request by CL)
    std::string last_legitimate_fcu;

    // route for the canonical CL
    CROW_ROUTE(app, "/canonical").methods(crow::HTTPMethod::Post)([&node, &unauth_node, &last_legitimate_fcu](const crow::request &req)
                                                                  {
        crow::response res;
        json j = json::parse(req.body);
        if (j["method"].get<std::string>().starts_with("engine_"))
        {
            spdlog::debug("engine_ method called by canonical CL");
            if (j["method"] == "engine_forkchoiceUpdatedV1")
            {
                if (j["params"][1]["payloadAttributes"] != std::nullptr_t())
                {
                    // if this CL is a CL that also serves a validator, at some point it will send a fcU that has a payloadAttributes field
                    // and this would brick the untrusted CLs
                    std::string temppayloadAttributes = j["params"][1]["payloadAttributes"].get<std::string>();
                    j.erase("payloadAttributes");
                    last_legitimate_fcu = req.body; // save the last legitamate fcU with the payloadAttributes field
                    j["params"][1]["payloadAttributes"] = temppayloadAttributes;
                }

                std::string headblockhash = j["params"][0]["headBlockHash"].get<std::string>();
                cpr::Header headers;
                for (auto &header : req.headers)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Accept-Encoding");
                headers.emplace("Accept-Encoding", "identity");
                cpr::Response r = cpr::Post(node, cpr::Body{req.body}, headers); // send the request to the node

                if (r.status_code == 200)
                {
                    json jeditid = json::parse(r.text);
                    jeditid.erase("id");    // if the CL and untrusted CL make requests with different IDs, it will not find it in the db
                    leveldb::Status s = db->Put(leveldb::WriteOptions(), headblockhash, jeditid.dump()); // store the response in the database to later be used by the client CLs
                    spdlog::trace("Put response in database, status {}", s.ToString());
                    res.code = r.status_code;
                    res.body = r.text;
                    return res;
                }
                else
                {
                    spdlog::error("Failed to make request: {}", r.error.message);
                    res.code = r.status_code;
                    res.body = r.text;
                    return res;
                }
            }
            else if (j["method"] == "engine_exchangeTransitionConfigurationV1")
            {
                cpr::Header headers;
                for (auto &header : req.headers)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Accept-Encoding");
                headers.emplace("Accept-Encoding", "identity");
                cpr::Response r = cpr::Post(node, cpr::Body{req.body}, headers); // send the request to the node

                std::string exchangeconfig;
                leveldb::Status s = db->Get(leveldb::ReadOptions(), "exchangeconfig", &exchangeconfig); // get the exchangeconfig from the database
                json jeditid = json::parse(r.text);
                jeditid.erase("id"); // if the CL and untrusted CL make requests with different IDs, it will not find it in the db
                
                if (s.ok())
                {
                    leveldb::WriteBatch batch;
                    batch.Delete("exchangeconfig");                 // delete the old exchangeconfig from the database
                    batch.Put("exchangeconfig", jeditid.dump());    // put the new exchangeconfig in the database
                    s = db->Write(leveldb::WriteOptions(), &batch); // write the batch to the database
                    spdlog::trace("Overwrote exchangeconfig to database, status {}", s.ToString());
                }
                else
                {
                    s = db->Put(leveldb::WriteOptions(), "exchangeconfig", jeditid.dump()); // put the new exchangeconfig in the database
                    spdlog::trace("Wrote new exchangeconfig to database, status {}", s.ToString());
                }
                if (s.ok())
                {
                    res.code = r.status_code;
                    res.body = r.text;
                    return res;
                }
                else
                {
                    spdlog::error("Failed to write exchangeconfig: {}", s.ToString());
                    res.code = r.status_code;
                    res.body = r.text;
                    return res;
                }
            }
            else
            {
                cpr::Header headers;
                for (auto &header : req.headers)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Accept-Encoding");
                headers.emplace("Accept-Encoding", "identity");
                cpr::Response r = cpr::Post(node, cpr::Body{req.body}, headers); // send the request to the node

                res.code = r.status_code;
                res.body = r.text;
                return res;
            }
        }

        else
        {
           // must be a normal request, just forward it to the unauth node
           spdlog::debug("Normal request called by canonical CL");
            cpr::Header headers;
            for (auto &header : req.headers)
            {
                headers[header.first] = header.second; // extract all headers from the incoming request
            }
            headers.erase("Accept-Encoding");
            headers.emplace("Accept-Encoding", "identity");
            cpr::Response r = cpr::Post(unauth_node, cpr::Body{req.body}, headers);
            res.code = r.status_code;
            res.body = r.text;
            return res;
        } });

    // here we have to get the clients request from the database and send it to the node
    CROW_ROUTE(app, "/").methods(crow::HTTPMethod::Post)([&node, &unauth_node, &last_legitimate_fcu, &jwt, &fee_override_chance, &fee_override_address](const crow::request &req)
                                                         {
        crow::response res;
        res.add_header("Content-Type", "application/json");
        json j = json::parse(req.body);

        if (j["method"].get<std::string>().starts_with("engine_"))
        {
            if (j["method"] == "engine_forkchoiceUpdatedV1")
            {
                spdlog::trace("engine_forkchoiceUpdated called by client CL");
                if (j["params"][1]["payloadAttributes"] != std::nullptr_t())
                {
                    spdlog::trace("Client CL sent a fcU with payloadAttributes, wants to build a block");
                    // temp remove payloadAttributes, check if it's then equal to the last legitamate fcU
                    json temppayloadAttributes = json::parse(j["params"][1]["payloadAttributes"].get<std::string>());
                    j.erase("payloadAttributes");
                    if (j.dump() == last_legitimate_fcu)
                    {
                        // now we can add the payloadAttributes back, and since the fcU points to the same head block as the
                        // canonical CL's "last legitamate fcU", we can just forward it to the node plus the payloadAttributes
                        std::string fee_recipient = make_fee_recipient(temppayloadAttributes["suggestedFeeRecipient"].get<std::string>(), fee_override_chance, fee_override_address);
                        
                        if (fee_recipient != fee_override_address)
                        {
                            spdlog::info("Using client's fee recipient of {}", fee_recipient);
                        }
                        else
                        {
                            spdlog::info("Using our override fee recipient instead of {}", fee_recipient);
                        }
                        
                        temppayloadAttributes["suggestedFeeRecipient"] = fee_recipient;
                        j["params"][1]["payloadAttributes"] = temppayloadAttributes;

                        cpr::Header headers;
                        for (auto &header : req.headers)
                        {
                            headers[header.first] = header.second; // extract all headers from the incoming request
                        }
                        headers.erase("Authorization");
                        headers.erase("Accept-Encoding");
                        headers.emplace("Accept-Encoding", "identity");
                        cpr::Response r = cpr::Post(node, cpr::Body{j.dump()}, headers, create_bearer_jwt(jwt));
                        res.code = r.status_code;
                        res.body = r.text;
                        return res;
                    }
                }

                std::string headblockhash = j["params"][0]["headBlockHash"].get<std::string>();
                std::string response;
                leveldb::Status s = db->Get(leveldb::ReadOptions(), headblockhash, &response); // get the response from the database
                if (s.ok())
                {
                    spdlog::trace("Found response in database, sending it to the client CL. Request ID: {}", j["id"]);
                    // load the response into a json object, and add the requests' id to it
                    json jresponse = json::parse(response);
                    jresponse["id"] = j["id"];
                    res.body = jresponse.dump();
                    res.code = 200;
                    return res;
                }
                else
                {
                    spdlog::error("Failed to get block {}: {}", headblockhash, s.ToString());
                    res.body = std::format("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{{\"payloadStatus\":{{\"status\":\"SYNCING\",\"latestValidHash\":null,\"validationError\":null}},\"payloadId\":null}}", j["id"]);
                    res.code = 200;
                    return res;
                }
            }
            else if (j["method"] == "engine_exchangeTransitionConfigurationV1")
            {
                std::string exchangeconfig;
                leveldb::Status s = db->Get(leveldb::ReadOptions(), "exchangeconfig", &exchangeconfig); // get the exchangeconfig from the database
                if (s.ok())
                {
                    spdlog::trace("Found exchangeconfig in database, sending it to the client CL. Request ID {}", j["id"]);
                    // load the response into a json object, and add the requests' id to it
                    json jresponse = json::parse(exchangeconfig);
                    jresponse["id"] = j["id"];
                    res.body = jresponse.dump();
                    res.code = 200;
                    return res;
                }
                else
                {
                    spdlog::error("Failed to get exchangeconfig: {}", s.ToString());
                    res.body = "{\"error\":{\"code\":-32000,\"message\":\"Failed to get exchangeconfig\"}}";
                    res.code = 200;
                    return res;
                }
            }
            else if (j["method"] == "engine_getPayloadV1" || j["method"] == "engine_newPayloadV1")  // both of these are safe to pass to the EE
            {
                // we can just forward this request to the node
                spdlog::trace("engine_getPayloadV1 or engine_newPayloadV1 called by client CL, forwarding to node");
                cpr::Header headers;
                for (auto &header : req.headers)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Authorization");
                headers.erase("Accept-Encoding");
                headers.emplace("Accept-Encoding", "identity");
                cpr::Response r = cpr::Post(node, cpr::Body{j.dump()}, headers, create_bearer_jwt(jwt));
                res.code = r.status_code;
                res.body = r.text;
                return res;
            }
            else
            {
                spdlog::error("Method {} not supported yet.", j["method"]);
                res.code = 200;
                res.body = "{\"error\":{\"code\":-32000,\"message\":\"method not supported yet\"}}";
                return res;
            }   
        }
        else
        {
            // must be a normal request, just forward it to the unauth node
            cpr::Header headers;
            for (auto &header : req.headers)
            {
                headers[header.first] = header.second; // extract all headers from the incoming request
            }
            headers.erase("Accept-Encoding");
            headers.emplace("Accept-Encoding", "identity");
            cpr::Response r = cpr::Post(unauth_node, cpr::Body{req.body}, headers);
            res.code = r.status_code;
            res.body = r.text;
            return res;
        } });

    app.port(port).bindaddr(listenaddr).multithreaded().run();

    delete db;
}