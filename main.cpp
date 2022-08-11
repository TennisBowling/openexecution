#include <cpr/cpr.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <leveldb/db.h>
#include <leveldb/cache.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <string>
#include <iostream>
#include <thread>
#include <signal.h>
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

    cpr::Url url{"http://192.168.86.109"};

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
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = signal_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    // setup crow
    crow::SimpleApp app;

    // route for the canonical CL
    CROW_ROUTE(app, "/canonical")
    ([](const crow::request &req)
     {
        json j = json::parse(req.body);
        if (json["method"].get<std::string>() == "engine_forkchoiceUpdatedV1")
        {

            std::string headblockhash = json["params"][0]["headBlockHash"].get<std::string>();
            cpr::Header headers;
            for (auto &header : req.headers)
            {
                headers[header.first] = header.second; // extract all headers from the incoming request
            }

            cpr::Response r = cpr::Post(url, cpr::Body{req.body}, headers); // send the request to the node

            if (r.status_code == 200)
            {
                leveldb::status s = db->Put(leveldb::WriteOptions(), headblockhash, r.text); // store the response in the database to later be used by the client CLs
            }
            else
            {
                spdlog::error("Failed to get block {}: {}", headblockhash, r.text);
            }
        }
        else if (json["method"].get<std::string>() == "engine_exchangeTransitionConfigurationV1")
        {
            cpr::Header headers;
            for (auto &header : req.headers)
            {
                headers[header.first] = header.second; // extract all headers from the incoming request
            }

            cpr::Response r = cpr::Post(url, cpr::Body{req.body}, headers); // send the request to the node

            std::string exchangeconfig;
            leveldb::status s = db->Get(leveldb::ReadOptions(), "exchangeconfig", &exchangeconfig); // get the exchangeconfig from the database
            if (s.ok())
            {
                leveldb::WriteBatch batch;
                batch.Delete("exchangeconfig");                 // delete the old exchangeconfig from the database
                batch.Put("exchangeconfig", r.text);            // put the new exchangeconfig in the database
                s = db->Write(leveldb::WriteOptions(), &batch); // write the batch to the database
            }
        } });

    // here we have to get the clients request from the database and send it to the node
    CROW_ROUTE(app, "/")
    ([](const crow::request &req) {
        crow::response res;
        res.add_header("Content-Type", "application/json");
        json j = json::parse(req.body);
        if (json["method"].get<std::string>() == "engine_forkchoiceUpdatedV1")
        {
            std::string headblockhash = json["params"][0]["headBlockHash"].get<std::string>();
            std::string response;
            leveldb::status s = db->Get(leveldb::ReadOptions(), headblockhash, &response); // get the response from the database
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
        else if (json["method"].get<std::string>() == "engine_exchangeTransitionConfigurationV1")
        {
            std::string exchangeconfig;
            leveldb::status s = db->Get(leveldb::ReadOptions(), "exchangeconfig", &exchangeconfig); // get the exchangeconfig from the database
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
            spdlog::error("method {} not supported yet.", json["method"].get<std::string>());
            return "";
        }

        );

        delete db;
}