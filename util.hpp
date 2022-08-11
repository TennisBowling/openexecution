#pragma once
#include <vector>
#include <string>
#include <future>
#include <unordered_map>
#include <fstream>
#include <cpr/cpr.h>
#include <boost/program_options.hpp>
#include <boost/config.hpp>
#include <spdlog/spdlog.h>
#include "Simple-Web-Server/server_http.hpp"
using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;

namespace Util
{
    cpr::Header multimap_to_cpr_header(SimpleWeb::CaseInsensitiveMultimap &headers)
    {
        cpr::Header h;
        for (auto &header : headers)
        {
            h[header.first] = header.second;
        }
        return h;
    }

    SimpleWeb::CaseInsensitiveMultimap cpr_header_to_multimap(cpr::Header &headers)
    {
        SimpleWeb::CaseInsensitiveMultimap h;
        for (auto &header : headers)
        {
            h.emplace(header.first, header.second);
        }
        return h;
    }

    boost::program_options::variables_map parse_args(int argc, char *argv[])
    {
        boost::program_options::options_description desc("Allowed options");
        desc.add_options()

            ("help,h", "produce help message")                                                                      // help message
            ("version,v", "print version")                                                                          // version message
            ("port,p", boost::program_options::value<int>(), "port to listen on")                                   // port to listen on
            ("listen-addr,addr", boost::program_options::value<std::string>(), "address to listen on for json-rpc") // listen addr
            ("node-ip,n", boost::program_options::value<std::string>(), "the ip of the \"canonical\" node");        // canonical node

        boost::program_options::variables_map vm;
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        boost::program_options::notify(vm);

        if (vm.count("help"))
        {
            std::cout << desc << std::endl;
            exit(0);
        }

        if (vm.count("version"))
        {
            std::cout << "openexecution version 0.1.0 BETA\n";
            std::cout << "Compiled with " << BOOST_COMPILER << std::endl;
            exit(0);
        }

        if (vm.count("node-ip") == 0)
        {
            spdlog::critical("no canonical node specified, exiting");
            exit(1);
        }

        if (vm.count("port") == 0)
        {
            spdlog::warn("no port specified, using default port 8000");
        }

        return vm;
    }
}