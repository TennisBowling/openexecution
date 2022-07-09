#include <cpr/cpr.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include "util.hpp"
#include "Simple-Web-Server/server_http.hpp"
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <string>
#include <iostream>
#include <pqxx/pqxx>

int main(int argc, char *argv[])
{
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] - %v"); // nice style that i like

    // setup postgres
    try
    {
        pqxx::connection db("postgresql://postgres:postgres@localhost:5432/postgres");
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
    }

    // pqxx::work txn(db);
    // txn.exec("CREATE TABLE IF NOT EXISTS fcu_data (VALUE TEXT);");
    // txn.commit();

    spdlog::info("Postgresql connection established");
}