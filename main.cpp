#include <cpr/cpr.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include "util.hpp"
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <string>
#include <iostream>

int main(int argc, char *argv[])
{
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S] [%^%l%$] - %v"); // nice style that i like

    // setup sqlite
    auto db = sqlitelib::Sqlite("db.sqlite");
    db.execute("CREATE TABLE IF NOT EXISTS fcu_data (VALUE TEXT);");

    spdlog::info("Sqlite connection established");
}