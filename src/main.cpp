#include <cpr/cpr.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <leveldb/db.h>
#include <leveldb/cache.h>
#include <leveldb/write_batch.h>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include "../Simple-Web-Server/server_http.hpp"
#include "util.hpp"
#include "wsrouter.hpp"
#include "../rust_jwt/rust_jwt.hpp"
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <random>

using json = nlohmann::json;
using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;



leveldb::DB *db;

SimpleWeb::CaseInsensitiveMultimap defaultheaders;

boost::asio::thread_pool pool(std::thread::hardware_concurrency());

void signal_handler(int signal)
{
    spdlog::info("Caught signal {}, closing databases.", signal);
    delete db;
    spdlog::info("Database closed.");
    exit(signal);
}

std::string create_bearer_jwt(std::string &token)
{
    const int64_t timestamp = static_cast<int64_t>(std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count());

    return make_jwt(token.data(), &timestamp); 
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

std::string make_request(std::string &node, std::optional<WebsocketRouter> &router, json &j, SimpleWeb::CaseInsensitiveMultimap& headers) // should route with ws or cpr
{
    if (router.has_value())
    {
        return router.value().wait_for(j).dump(); // send the request to the websocket router
    }
    else
    {
        cpr::Header cprheaders;
        for (auto &header : headers)
        {
            cprheaders[header.first] = header.second; // extract all headers from the incoming request
        }
        cprheaders.erase("Host"); // prevent vhosts checks from failing
        cprheaders.erase("Accept-Encoding");
        cprheaders.emplace("Accept-Encoding", "identity");

        cpr::Response r = cpr::Post(cpr::Url{node}, cpr::Body{j.dump()}, cprheaders); // send the request to the node
        return r.text;
    }
}

int main(int argc, char *argv[])
{
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] - %v"); // nice style that i like

    defaultheaders.emplace("Accept-Encoding", "identity");
    defaultheaders.emplace("Content-Type", "application/json");

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

    // make either a websocket router or a cpr client
    std::string node;
    std::string unauthnode;
    std::optional<WebsocketRouter> noderouter;
    std::optional<WebsocketRouter> unauthnoderouter;
    std::optional<cpr::Url> nodeurl;
    std::optional<cpr::Url> unauthnodeurl;
    net::io_context ioc;
    if (vm.count("node") == 0 && vm.count("ws-node") != 0) {
        // create router
        node = vm["ws-node"].as<std::string>();
        std::string host = node.substr(0, node.find(":"));
        std::string port = node.substr(node.find(":") + 1);
        noderouter.emplace(host, port, ioc);
    }
    else if (vm.count("node") != 0 && vm.count("ws-node") == 0) {
        // create cpr client
        node = vm["node"].as<std::string>();
        nodeurl.emplace(cpr::Url{node});
    }

    // same as above but for unauth
    if (vm.count("unauth-node") == 0 && vm.count("ws-unauth-node") != 0) {
        // create router
        unauthnode = vm["ws-unauth-node"].as<std::string>();
        std::string host = unauthnode.substr(0, unauthnode.find(":"));
        std::string port = unauthnode.substr(unauthnode.find(":") + 1);
        unauthnoderouter.emplace(host, port, ioc);
    }
    else if (vm.count("unauth-node") != 0 && vm.count("ws-unauth-node") == 0) {
        // create cpr client
        unauthnode = vm["unauth-node"].as<std::string>();
        unauthnodeurl.emplace(cpr::Url{unauthnode});
    }


    auto jwt = read_jwt(vm["jwt-secret"].as<std::string>());

    // setup rocksdb
    leveldb::Options options;
    options.create_if_missing = true;
    options.block_cache = leveldb::NewLRUCache(3145728); // 3MB cache
    // TODO: add caching
    leveldb::Status status = leveldb::DB::Open(options, "./db", &db);
    if (!status.ok())
    {
        spdlog::error("Failed to open database: {}", status.ToString());
        return 1;
    }

    // setup threadpool
    boost::asio::post(pool, [&]()
                      { spdlog::info("Starting threadpool with {} threads", std::thread::hardware_concurrency()); });

    // setup http server
    HttpServer server;
    server.config.port = port;
    server.config.address = listenaddr;

    // setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    spdlog::debug("Signal handler set.");

    // last legitamate fcU (request by CL)
    std::string last_legitimate_fcu;

    // route for the canonical CL
    try {
        server.resource["/canonical"]["POST"] = [&node, &unauthnode, &noderouter, &unauthnoderouter, &nodeurl, &unauthnodeurl, &last_legitimate_fcu](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request)
        {
            boost::asio::post(pool, [&node, &unauthnode, &noderouter, &unauthnoderouter, &nodeurl, &unauthnodeurl, &last_legitimate_fcu, response, request]()
                            {
                std::string body = request->content.string();
                json j = json::parse(body);
                if (j["method"].get<std::string>().starts_with("engine_"))
                {
                    spdlog::debug("engine_ method called by canonical CL");
                    if (j["method"] == "engine_forkchoiceUpdatedV1" || j["method"] == "engine_forkchoiceUpdatedV2")
                    {
                        if (j["params"][1].contains("payloadAttributesV1") || j["params"][1].contains("payloadAttributesV2"))
                        {
                            // if this CL is a CL that also serves a validator, at some point it will send a fcU that has a payloadAttributes field
                            // and this would brick the untrusted CLs
                            std::string temppayloadAttributes = j["params"][1]["payloadAttributes"].get<std::string>();
                            j.erase("payloadAttributes");
                            last_legitimate_fcu = body; // save the last legitamate fcU with the payloadAttributes field
                            j["params"][1]["payloadAttributes"] = temppayloadAttributes;
                        }

                        std::string headblockhash = j["params"][0]["headBlockHash"].get<std::string>();
                        // make request to node
                        std::string resp = make_request(node, noderouter, j, request->header);

                        if (!resp.empty())
                        {
                            json jeditid = json::parse(resp);
                            jeditid.erase("id");                                                                 // if the CL and untrusted CL make requests with different IDs, it will not find it in the db
                            leveldb::Status s = db->Put(leveldb::WriteOptions(), headblockhash, jeditid.dump()); // store the response in the database to later be used by the client CLs
                            if (!s.ok())
                            {
                                spdlog::error("Failed to store response for block hash: {} in database: {}", headblockhash, s.ToString());
                                response->write(status_code_to_enum[500], "Failed to store response in database");
                                return;
                            }
                            else
                            {
                                spdlog::debug("Stored response for block hash: {} in database", headblockhash);
                            }
                            response->write(status_code_to_enum[200], resp);
                            return;
                        }
                        else
                        {
                            spdlog::error("Failed to make request to canonical node");
                            response->write(status_code_to_enum[500], "Failed to make request to canonical node");
                            return;
                        }
                    }
                    else if (j["method"] == "engine_newPayloadV1" || j["method"] == "engine_newPayloadV2")
                    {
                        // make request to node
                        std::string resp = make_request(node, noderouter, j, request->header);

                        if (!resp.empty())
                        {
                            json jeditid = json::parse(resp);
                            jeditid.erase("id"); // if the CL and untrusted CL make requests with different IDs, it will not find it in the db
                            leveldb::Status s = db->Put(leveldb::WriteOptions(), j["params"][0]["blockHash"].get<std::string>(), jeditid.dump()); // store the response in the database to later be used by the client CLs
                            if (!s.ok())
                            {
                                spdlog::error("Failed to store response for block hash: {} in database: {}", j["params"][0]["blockHash"].get<std::string>(), s.ToString());
                                response->write(status_code_to_enum[500], "Failed to store response in database");
                                return;
                            }
                            else
                            {
                                spdlog::debug("Stored response for block hash: {} in database", j["params"][0]["blockHash"].get<std::string>());
                            }
                            response->write(status_code_to_enum[200], resp);
                            return;
                        }
                        else
                        {
                            spdlog::error("Failed to make request to canonical node");
                            response->write(status_code_to_enum[500], "Failed to make request to canonical node");
                            return;
                        }
                    }
                    else if (j["method"] == "engine_exchangeTransitionConfigurationV1")
                    {
                        // make request to node
                        std::string resp = make_request(node, noderouter, j, request->header);

                        std::string exchangeconfig;
                        leveldb::Status s = db->Get(leveldb::ReadOptions(), "exchangeconfig", &exchangeconfig); // get the exchangeconfig from the database
                        json jeditid = json::parse(resp);
                        jeditid.erase("id"); // if the CL and untrusted CL make requests with different IDs, it will not find it in the db

                        if (s.ok())
                        {
                            leveldb::WriteBatch batch;
                            batch.Delete("exchangeconfig");                 // delete the old exchangeconfig from the database
                            batch.Put("exchangeconfig", jeditid.dump());    // put the new exchangeconfig in the database
                            s = db->Write(leveldb::WriteOptions(), &batch); // write the batch to the database
                            spdlog::debug("Overwrote exchangeconfig to database, status {}", s.ToString());
                        }
                        else
                        {
                            s = db->Put(leveldb::WriteOptions(), "exchangeconfig", jeditid.dump()); // put the new exchangeconfig in the database
                            spdlog::debug("Wrote new exchangeconfig to database, status {}", s.ToString());
                        }
                        if (s.ok())
                        {
                            response->write(status_code_to_enum[200], resp); // send the old exchangeconfig to the client CLs
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
                        // make request to node
                        std::string resp = make_request(node, noderouter, j, request->header);

                        response->write(status_code_to_enum[200], resp);
                        return;
                    }
                }

                else
                {
                    // must be a normal request, just forward it to the unauth node
                    spdlog::debug("Normal request called by canonical CL");
                    std::string resp = make_request(unauthnode, unauthnoderouter, j, request->header);
                    response->write(status_code_to_enum[200], resp);
                } });
        };

        // here we have to get the clients request from the database and send it to the node
        server.resource["/"]["POST"] = [&node, &unauthnode, &noderouter, &unauthnoderouter, &nodeurl, &unauthnodeurl, &last_legitimate_fcu, &jwt, &fee_override_chance, &fee_override_address](std::shared_ptr<HttpServer::Response> response, std::shared_ptr<HttpServer::Request> request)
        {
            boost::asio::post(pool, [&node, &unauthnode, &noderouter, &unauthnoderouter, &nodeurl, &unauthnodeurl, &last_legitimate_fcu, &jwt, &fee_override_chance, &fee_override_address, response, request]()
                            {
                std::string body = request->content.string();
                json j = json::parse(body);

                if (j["method"].get<std::string>().starts_with("engine_"))
                {
                    if (j["method"] == "engine_forkchoiceUpdatedV1" || j["method"] == "engine_forkchoiceUpdatedV2")
                    {
                        spdlog::debug("engine_forkchoiceUpdated called by client CL");
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

                                // make request with default headers and add the jwt to it
                                auto defaultheadercopy = request->header;
                                defaultheadercopy.emplace("Authorization", "Bearer " + create_bearer_jwt(jwt));
                                std::string resp = make_request(node, noderouter, j, defaultheadercopy);
                                response->write(status_code_to_enum[200], resp);
                                return;
                            }
                            else {
                                spdlog::debug("Client CL sent a fcU with payloadAttributes, but it's not equal to the last legitamate fcU, so we can't forward it to the node");
                                response->write(status_code_to_enum[200], "{\"error\":{\"code\":-32000,\"message\":\"Cannot let you build a block with an invalid fcU\"}}");
                                return;
                            }

                        }

                        std::string headblockhash = j["params"][0]["headBlockHash"].get<std::string>();
                        std::string responsestr;
                        for (int i = 0; i < 5; i++) // will iterate 5 times to try and get the response from the db as the canonical CL might not have written to it yet
                        {
                            leveldb::Status s = db->Get(leveldb::ReadOptions(), headblockhash, &responsestr); // get the response from the database
                            if (s.ok())
                            {
                                spdlog::debug("Found response in database, sending it to the client CL. Request ID: {}", j["id"]);
                                // load the response into a json object, and add the requests' id to it
                                json jresponse = json::parse(responsestr);
                                jresponse["id"] = j["id"];
                                response->write(status_code_to_enum[200], jresponse.dump());
                                return;
                            }
                            else
                            {
                                spdlog::error("Failed to get block {}: {}", headblockhash, s.ToString());
                                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                                continue;
                            }
                        }
                        spdlog::error("Failed to get block {} from database after 5 tries", headblockhash);
                        json jresponse = json::parse("{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{\"payloadStatus\":{\"status\":\"SYNCING\",\"latestValidHash\":null,\"validationError\":null},\"payloadId\":null}}");
                        jresponse["id"] = j["id"];
                        response->write(status_code_to_enum[200], jresponse.dump());
                        return;
                    }
                    else if (j["method"] == "engine_exchangeTransitionConfigurationV1")
                    {
                        std::string exchangeconfig;
                        leveldb::Status s = db->Get(leveldb::ReadOptions(), "exchangeconfig", &exchangeconfig); // get the exchangeconfig from the database
                        if (s.ok())
                        {
                            spdlog::debug("Found exchangeconfig in database, sending it to the client CL. Request ID {}", j["id"]);
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
                    else if (j["method"] == "engine_newPayloadV1" || j["method"] == "engine_newPayloadV2") {
                        // get from db or make a request to auth node if not found
                        spdlog::debug("engine_newPayload called by non-canonical CL, getting response from database or auth node");
                        std::string blockhash = j["params"][0]["blockHash"].get<std::string>();
                        std::string responsestr;
                        leveldb::Status s = db->Get(leveldb::ReadOptions(), blockhash, &responsestr); // get the response from the database
                        
                        if (s.ok() && !responsestr.empty()) {
                            // load the response into a json object, and add the requests' id to it
                            json jresponse = json::parse(responsestr);
                            jresponse["id"] = j["id"];
                            response->write(status_code_to_enum[200], jresponse.dump()); // send the response to the client CL
                        }
                        else {
                            // forward the request to the auth node
                            auto defaultheadercopy = request->header;
                            defaultheadercopy.emplace("Authorization", "Bearer " + create_bearer_jwt(jwt));
                            std::string resp = make_request(node, noderouter, j, defaultheadercopy);
                            response->write(status_code_to_enum[200], resp);
                        }
                    }

                    else if (j["method"] == "engine_getPayloadV1" || j["method"] == "engine_getPayloadV2" ||
                    j["method"] == "engine_getPayloadBodiesByHashV1" || j["method"] == "engine_getPayloadBodiesByRangeV1" ||
                    j["method"] == "engine_exchangeCapabilities") // safe to pass to the EE
                    {
                        // we can just forward this request to the node
                        spdlog::debug("{}} called by non-canonical CL, forwarding to node", j["method"]);

                        auto defaultheadercopy = request->header;
                        defaultheadercopy.emplace("Authorization", "Bearer " + create_bearer_jwt(jwt));
                        std::string resp = make_request(node, noderouter, j, defaultheadercopy);
                        response->write(status_code_to_enum[200], resp);
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
                    auto defaultheadercopy = request->header;
                    defaultheadercopy.emplace("Authorization", "Bearer " + create_bearer_jwt(jwt));
                    std::string resp = make_request(unauthnode, unauthnoderouter, j, defaultheadercopy);
                    response->write(status_code_to_enum[200], resp);
                    return;
                } });
        };
    }
    catch (const std::exception& e)
    {
        spdlog::error("Exception: {}", e.what());
    }

    server.start();

    delete db;
}