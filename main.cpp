#include <cpr/cpr.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <leveldb/db.h>
#include <leveldb/cache.h>
#include <leveldb/write_batch.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include "Simple-Web-Server/server_http.hpp"
#include "util.hpp"
#include "rust_jwt/rust_jwt.hpp"
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <random>
using json = nlohmann::json;
using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;

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

    // setup http server
    HttpServer server;
    server.config.port = port;
    server.config.address = listenaddr;

    // setup signal handler
    signal(SIGINT, signal_handler);
    spdlog::debug("Signal handler set.");

    // last legitamate fcU (request by CL)
    std::string last_legitimate_fcu;

    // route for the canonical CL
    server.resource["/canonical"]["POST"] = [&node, &unauth_node, &last_legitimate_fcu](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request)
    {
        std::string body = request->content.string();
        json j = json::parse(body);
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
                    last_legitimate_fcu = body; // save the last legitamate fcU with the payloadAttributes field
                    j["params"][1]["payloadAttributes"] = temppayloadAttributes;
                }

                std::string headblockhash = j["params"][0]["headBlockHash"].get<std::string>();
                cpr::Header headers;
                for (auto &header : request->header)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Accept-Encoding");
                headers.emplace("Accept-Encoding", "identity");
                cpr::Response r = cpr::Post(node, cpr::Body{body}, headers); // send the request to the node

                if (r.status_code == 200)
                {
                    json jeditid = json::parse(r.text);
                    jeditid.erase("id");                                                                 // if the CL and untrusted CL make requests with different IDs, it will not find it in the db
                    leveldb::Status s = db->Put(leveldb::WriteOptions(), headblockhash, jeditid.dump()); // store the response in the database to later be used by the client CLs
                    spdlog::trace("Put response in database, status {}", s.ToString());
                    response->write(status_code_to_enum[r.status_code], r.text);
                    return;
                }
                else
                {
                    spdlog::error("Failed to make request: {}", r.error.message);
                    response->write(status_code_to_enum[r.status_code], r.text);
                    return;
                }
            }
            else if (j["method"] == "engine_exchangeTransitionConfigurationV1")
            {
                cpr::Header headers;
                for (auto &header : request->header)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Accept-Encoding");
                headers.emplace("Accept-Encoding", "identity");
                cpr::Response r = cpr::Post(node, cpr::Body{body}, headers); // send the request to the node

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
                    response->write(status_code_to_enum[r.status_code], r.text); // send the old exchangeconfig to the client CLs
                    return;
                }
                else
                {
                    spdlog::error("Failed to write to database: {}", s.ToString());
                    response->write(status_code_to_enum[500], "Failed to write to database");
                    return;
                }
            }
            else
            {
                cpr::Header headers;
                for (auto &header : request->header)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Accept-Encoding");
                headers.emplace("Accept-Encoding", "identity");
                cpr::Response r = cpr::Post(node, cpr::Body{body}, headers); // send the request to the node

                response->write(status_code_to_enum[r.status_code], r.text);
                return;
            }
        }

        else
        {
            // must be a normal request, just forward it to the unauth node
            spdlog::debug("Normal request called by canonical CL");
            cpr::Header headers;
            for (auto &header : request->header)
            {
                headers[header.first] = header.second; // extract all headers from the incoming request
            }
            headers.erase("Accept-Encoding");
            headers.emplace("Accept-Encoding", "identity");
            cpr::Response r = cpr::Post(unauth_node, cpr::Body{body}, headers);
            response->write(status_code_to_enum[r.status_code], r.text);
        }
    };

    // here we have to get the clients request from the database and send it to the node
    server.resource["/"]["POST"] = [&node, &unauth_node, &last_legitimate_fcu, &jwt, &fee_override_chance, &fee_override_address](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request)
    {
        std::string body = request->content.string();
        json j = json::parse(body);

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
                        for (auto &header : request->header)
                        {
                            headers[header.first] = header.second; // extract all headers from the incoming request
                        }
                        headers.erase("Authorization");
                        headers.erase("Accept-Encoding");
                        headers.emplace("Accept-Encoding", "identity");
                        cpr::Response r = cpr::Post(node, cpr::Body{j.dump()}, headers, create_bearer_jwt(jwt));
                        response->write(status_code_to_enum[r.status_code], r.text);
                        return;
                    }
                }

                std::string headblockhash = j["params"][0]["headBlockHash"].get<std::string>();
                std::string responsestr;
                leveldb::Status s = db->Get(leveldb::ReadOptions(), headblockhash, &responsestr); // get the response from the database
                if (s.ok())
                {
                    spdlog::trace("Found response in database, sending it to the client CL. Request ID: {}", j["id"].dump());
                    // load the response into a json object, and add the requests' id to it
                    json jresponse = json::parse(responsestr);
                    jresponse["id"] = j["id"];
                    response->write(status_code_to_enum[200], jresponse.dump());
                    return;
                }
                else
                {
                    spdlog::error("Failed to get block {}: {}", headblockhash, s.ToString());
                    json jresponse = json::parse("{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{\"payloadStatus\":{\"status\":\"SYNCING\",\"latestValidHash\":null,\"validationError\":null},\"payloadId\":null}}");
                    jresponse["id"] = j["id"];
                    response->write(status_code_to_enum[200], jresponse.dump());
                    return;
                }
            }
            else if (j["method"] == "engine_exchangeTransitionConfigurationV1")
            {
                std::string exchangeconfig;
                leveldb::Status s = db->Get(leveldb::ReadOptions(), "exchangeconfig", &exchangeconfig); // get the exchangeconfig from the database
                if (s.ok())
                {
                    spdlog::trace("Found exchangeconfig in database, sending it to the client CL. Request ID: {}", j["id"].dump());
                    // load the response into a json object, and add the requests' id to it
                    json jresponse = json::parse(exchangeconfig);
                    jresponse["id"] = j["id"];
                    response->write(status_code_to_enum[200], jresponse.dump());
                    return;
                }
                else
                {
                    spdlog::error("Failed to get exchangeconfig: {}", s.ToString());
                    response->write(status_code_to_enum[200], "{\"error\":{\"code\":-32000,\"message\":\"Failed to get exchangeconfig\"}}");
                    return;
                }
            }
            else if (j["method"] == "engine_getPayloadV1" || j["method"] == "engine_newPayloadV1") // both of these are safe to pass to the EE
            {
                // we can just forward this request to the node
                spdlog::trace("engine_getPayloadV1 or engine_newPayloadV1 called by client CL, forwarding to node");
                cpr::Header headers;
                for (auto &header : request->header)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Authorization");
                headers.erase("Accept-Encoding");
                headers.emplace("Accept-Encoding", "identity");
                cpr::Response r = cpr::Post(node, cpr::Body{j.dump()}, headers, create_bearer_jwt(jwt));
                response->write(status_code_to_enum[r.status_code], r.text);
                return;
            }
            else
            {
                spdlog::error("Method {} not supported yet.", j["method"]);
                response->write(status_code_to_enum[200], "{\"error\":{\"code\":-32000,\"message\":\"Method not supported yet\"}}");
                return;
            }
        }
        else
        {
            // must be a normal request, just forward it to the unauth node
            cpr::Header headers;
            for (auto &header : request->header)
            {
                headers[header.first] = header.second; // extract all headers from the incoming request
            }
            headers.erase("Accept-Encoding");
            headers.emplace("Accept-Encoding", "identity");
            cpr::Response r = cpr::Post(unauth_node, cpr::Body{body}, headers);
            response->write(status_code_to_enum[r.status_code], r.text);
            return;
        }
    };

    server.start();

    delete db;
}
