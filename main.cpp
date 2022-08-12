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
#include <string>
#include <iostream>
#include <thread>
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

    std::string node = vm["node-ip"].as<std::string>();
    cpr::Url url{node};

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

    // setup signal handler
    signal(SIGINT, signal_handler);

    // setup crow
    crow::SimpleApp app;

    // route for the canonical CL
    CROW_ROUTE(app, "/canonical")
    ([&node, &db](const crow::request &req)
     {
        crow::response res;
        json j = json::parse(req.body);
        if (j["method"].get<std::string>() == "engine_forkchoiceUpdatedV1")
        {

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
                spdlog::error("Failed to get block {}: {}", headblockhash, r.text);
                res.code = r.status_code;
                res.body = r.text;
                return res;
            }
        }
        else if (j["method"].get<std::string>() == "engine_exchangeTransitionConfigurationV1")
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
        } });

    // here we have to get the clients request from the database and send it to the node
    CROW_ROUTE(app, "/")
    ([](const crow::request &req)
     {
         crow::response res;
         res.add_header("Content-Type", "application/json");
         json j = json::parse(req.body);
         if (j["method"].get<std::string>() == "engine_forkchoiceUpdatedV1")
         {
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
         else if (j["method"].get<std::string>() == "engine_exchangeTransitionConfigurationV1")
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
                 res.body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"payloadStatus\":{\"status\":\"SYNCING\",\"latestValidHash\":null,\"validationError\":null},\"payloadId\":null}}";
                 res.code = 200;
                 return res;
             }
         }
         else
         {
             spdlog::error("method {} not supported yet.", j["method"].get<std::string>());
             res.code = 200;
             res.body = "{\"error\" :\"method not supported yet.\"}";
             return res;
         } });

    app.port(port).bindaddr(listenaddr).multithreaded().run();

    delete db;
}