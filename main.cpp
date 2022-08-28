#include <cpr/cpr.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <leveldb/db.h>
#include <leveldb/cache.h>
#include <leveldb/write_batch.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <crow.h>
#include "util.hpp"
#include "crow_log.hpp"
#include "rust_jwt/rust_jwt.hpp"
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
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

    // last legitamate fcU (request by CL)
    std::string last_legitimate_fcu;

    // route for the canonical CL
    CROW_ROUTE(app, "/canonical").methods(crow::HTTPMethod::Post)([&node, &unauth_node, &last_legitimate_fcu](const crow::request &req)
                                                                  {
        crow::response res;
        json j = json::parse(req.body);
        if (j["method"].get<std::string>().starts_with("engine_"))
        {
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
                
                cpr::Response r = cpr::Post(node, cpr::Body{req.body}, headers); // send the request to the node

                if (r.status_code == 200)
                {
                    leveldb::Status s = db->Put(leveldb::WriteOptions(), headblockhash, r.text); // store the response in the database to later be used by the client CLs
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

                cpr::Response r = cpr::Post(node, cpr::Body{req.body}, headers); // send the request to the node

                std::string exchangeconfig;
                leveldb::Status s = db->Get(leveldb::ReadOptions(), "exchangeconfig", &exchangeconfig); // get the exchangeconfig from the database
                if (s.ok())
                {
                    leveldb::WriteBatch batch;
                    batch.Delete("exchangeconfig");                 // delete the old exchangeconfig from the database
                    batch.Put("exchangeconfig", r.text);            // put the new exchangeconfig in the database
                    s = db->Write(leveldb::WriteOptions(), &batch); // write the batch to the database
                }
                else
                {
                    s = db->Put(leveldb::WriteOptions(), "exchangeconfig", r.text); // put the new exchangeconfig in the database
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

                cpr::Response r = cpr::Post(node, cpr::Body{req.body}, headers); // send the request to the node

                res.code = r.status_code;
                res.body = r.text;
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
            cpr::Response r = cpr::Post(unauth_node, cpr::Body{req.body}, headers);
            res.code = r.status_code;
            res.body = r.text;
            return res;
        } });

    // here we have to get the clients request from the database and send it to the node
    CROW_ROUTE(app, "/").methods(crow::HTTPMethod::Post)([&node, &unauth_node, &last_legitimate_fcu, &jwt](const crow::request &req)
                                                         {
        crow::response res;
        res.add_header("Content-Type", "application/json");
        json j = json::parse(req.body);

        if (j["method"].get<std::string>().starts_with("engine_"))
        {
            if (j["method"] == "engine_forkchoiceUpdatedV1")
            {
                if (j["params"][1]["payloadAttributes"] != std::nullptr_t())
                {
                    // temp remove payloadAttributes, check if it's then equal to the last legitamate fcU
                    std::string temppayloadAttributes = j["params"][1]["payloadAttributes"].get<std::string>();
                    j.erase("payloadAttributes");
                    if (j.dump() == last_legitimate_fcu)
                    {
                        // now we can add the payloadAttributes back, and since the fcU points to the same head block as the
                        // canonical CL's "last legitamate fcU", we can just forward it to the node plus the payloadAttributes
                        j["params"][1]["payloadAttributes"] = temppayloadAttributes;
                        cpr::Header headers;
                        for (auto &header : req.headers)
                        {
                            headers[header.first] = header.second; // extract all headers from the incoming request
                        }
                        headers.erase("Authorization");
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
                    res.body = response;
                    res.code = 200;
                    return res;
                }
                else
                {
                    spdlog::error("Failed to get block {}: {}", headblockhash, s.ToString());
                    res.body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"payloadStatus\":{\"status\":\"SYNCING\",\"latestValidHash\":null,\"validationError\":null},\"payloadId\":null}}";
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
                    res.body = exchangeconfig;
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
                cpr::Header headers;
                for (auto &header : req.headers)
                {
                    headers[header.first] = header.second; // extract all headers from the incoming request
                }
                headers.erase("Authorization");
                cpr::Response r = cpr::Post(node, cpr::Body{j.dump()}, headers, create_bearer_jwt(jwt));
                res.code = r.status_code;
                res.body = r.text;
                return res;
            }
            else
            {
                spdlog::error("method {} not supported yet.", j["method"]);
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
            cpr::Response r = cpr::Post(unauth_node, cpr::Body{req.body}, headers);
            res.code = r.status_code;
            res.body = r.text;
            return res;
        } });

    app.port(port).bindaddr(listenaddr).multithreaded().run();

    delete db;
}