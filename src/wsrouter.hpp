#include <string>
#include <unordered_map>
#include <functional>
#include <memory>
#include <future>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <nlohmann/json.hpp>

using tcp = boost::asio::ip::tcp;
namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;
namespace beast = boost::beast;
namespace net = boost::asio;
using json = nlohmann::json;

/*
outgoing: subscribe to newHead
resp: {"jsonrpc":"2.0","id":0,"result":"0x28aec5f9d5c76bf536b10c7b9ec13de3"} (result is subscription id)
resp: {
  "jsonrpc": "2.0",
  "method": "eth_subscription",
  "params": {
    "result": {...},
    "subscription": "0x9ce59a13059e417087c02d3236a0b1cc"
  }
}*/

struct ResponseKey // key for the response map
{
    std::string id;
    bool is_sub_id_only; // will be something like {"jsonrpc":"2.0","id":0,"result":"0x28aec5f9d5c76bf536b10c7b9ec13de3"} (result is subscription id)
    bool is_sub; // will be something like {"jsonrpc":"2.0","method":"eth_subscription","params":{"result":{...},"subscription":"0x9ce59a13059e417087c02d3236a0b1cc"}}

    bool operator==(const ResponseKey& other) const {
        return id == other.id && is_sub_id_only == other.is_sub_id_only && is_sub == other.is_sub;
    }
};

namespace std {
    template <>
    struct hash<ResponseKey> {
        size_t operator()(const ResponseKey& key) const {
            return hash<string>()(key.id) ^ hash<bool>()(key.is_sub_id_only) ^ hash<bool>()(key.is_sub);
        }
    };
}

struct ResponseValue // value for the response map
{
    std::shared_ptr<std::promise<json>> promise;
    bool is_sub; // will be something like {"jsonrpc":"2.0","method":"eth_subscription","params":{"result":{...},"subscription":"0x9ce59a13059e417087c02d3236a0b1cc"}}
    void reset() {
        promise = std::make_shared<std::promise<json>>();
    }
};

class WebsocketRouter {
    public:
    // map of subscription ids to futures
    std::shared_ptr<std::unordered_map<ResponseKey, ResponseValue>> subscriptions;
    std::shared_ptr<net::io_context> ioc;
    tcp::resolver resolver;
    websocket::stream<tcp::socket> ws;
    int next_id = 0;

    WebsocketRouter(std::string host, std::string port, net::io_context &ioc) 
        : resolver(ioc), ws(ioc), subscriptions(std::make_shared<std::unordered_map<ResponseKey, ResponseValue>>()), next_id(0) {

        // connect to the websocket
        auto const results = resolver.resolve(host, port);
        auto ep = net::connect(ws.next_layer(), results);
        host += ':' + std::to_string(ep.port());
        ws.handshake(host, "/");

        // start the read loop
        std::thread([this]() {
            while (true) {
                beast::flat_buffer buffer;
                ws.read(buffer);
                std::string s = beast::buffers_to_string(buffer.data());


                //std::cout << "received: " << s << std::endl;
                json j;
                try {
                    j = json::parse(s);
                }
                catch (std::exception &e) {
                    std::cout << "error parsing json: " << e.what() << std::endl;
                    continue;
                }
                if (j.contains("id")) {
                    // this is a response to a single request OR sub id response
                    std::string id = std::to_string(j["id"].get<int>());
                    auto it = subscriptions->find(ResponseKey{id, false, false});
                    if (it != subscriptions->end()) {
                        it->second.promise->set_value(j);
                        // stop
                        subscriptions->erase(it);
                    }
                    else {
                        it = subscriptions->find(ResponseKey{id, true, false});
                        if (it != subscriptions->end()) {
                            // this is a resp to a subscription id ex: {"jsonrpc":"2.0","id":0,"result":"0x28aec5f9d5c76bf536b10c7b9ec13de3"} (result is subscription id)
                            std::string sub_id = j["result"];
                            std::shared_ptr<std::promise<json>> emptypromise = std::make_shared<std::promise<json>>();
                            subscriptions->insert({ResponseKey{sub_id, false, true}, ResponseValue{emptypromise, true}});
                            // return the new sub id
                            it->second.promise->set_value(j);
                            // stop
                            subscriptions->erase(it);
                        }
                    }


                }
                else if (j.contains("method") && j["method"] == "eth_subscription" && j.contains("params") && j["params"].contains("subscription")) {
                    // this is a resp to a subscription ex: {"jsonrpc":"2.0","method":"eth_subscription","params":{"result":{...},"subscription":"0x9ce59a13059e417087c02d3236a0b1cc"}}
                    std::string sub_id = j["params"]["subscription"];
                    auto it = subscriptions->find(ResponseKey{sub_id, false, true});
                    if (it != subscriptions->end()) {
                        it->second.promise->set_value(j["params"]["result"]);
                        it->second.reset();
                    }
                }


            }
        }).detach();
    }


    // single request
    json wait_for(json &j) {
        // send the request
        std::string s = j.dump();
        //std::cout << "sending: " << s << std::endl;
        ws.write(net::buffer(s));

        // wait for the response
        std::shared_ptr<std::promise<json>> promise = std::make_shared<std::promise<json>>();
        subscriptions->insert({ResponseKey{std::to_string(j["id"].get<int>()), false, false}, ResponseValue{promise, false}});
        return promise->get_future().get();
    }

    // sub creation
    std::string create_sub(json &j) {
        // send the request
        std::string s = j.dump();
        //std::cout << "sending: " << s << std::endl;
        ws.write(net::buffer(s));

        // wait for the response
        std::shared_ptr<std::promise<json>> promise = std::make_shared<std::promise<json>>();
        subscriptions->insert({ResponseKey{std::to_string(j["id"].get<int>()), true, false}, ResponseValue{promise, false}});
        json resp = promise->get_future().get();
        // update the map to say that the next resp will be a sub
        subscriptions->insert({ResponseKey{resp["result"], false, true}, ResponseValue{promise, true}});
        subscriptions->erase(ResponseKey{std::to_string(j["id"].get<int>()), true, false});
        return resp["result"];
    }

    // get the next sub response
    json get_sub(std::string &sub_id) {
        // no need to insert into the map, the sub id is already there
        auto it = subscriptions->find(ResponseKey{sub_id, false, true});
        if (it != subscriptions->end()) {
            return it->second.promise->get_future().get();
        }
        else {
            return json();
        }
    }

    // cancel a sub
    void cancel_sub(std::string sub_id) {
        subscriptions->erase(ResponseKey{sub_id, false, true});
    }
};