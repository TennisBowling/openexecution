#pragma once
#include <vector>
#include <string>
#include <future>
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <cpr/cpr.h>
#include <boost/program_options.hpp>
#include <boost/config.hpp>
#include <spdlog/spdlog.h>

std::string read_jwt(const std::string &filepath)
{
    std::ifstream filestream(filepath);

    if (filestream.is_open())
    {
        std::string jwt;
        filestream >> jwt;

        if (!jwt.starts_with("0x"))
        {
            spdlog::critical("JWT token is not properly formatted");
        }

        jwt.erase(0, 2); // remove the "0x" prefix
        return jwt;
    }
    else
    {
        spdlog::error("Unable to open file {} for the JWT secret.", filepath);
        exit(1);
    }
}

boost::program_options::variables_map parse_args(int argc, char *argv[])
{
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()

        ("help,h", "produce help message")                                                                      // help message
        ("version,v", "print version")                                                                          // version message
        ("port,p", boost::program_options::value<int>(), "port to listen on")                                   // port to listen on
        ("listen-addr,addr", boost::program_options::value<std::string>(), "address to listen on for json-rpc") // listen addr
        ("jwt-secret,jwt", boost::program_options::value<std::string>(), "filepath for the jwt secret")         // jwt-secret
        ("node,n", boost::program_options::value<std::string>(), "the ip of the \"canonical\" node");        // canonical node

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

    if (vm.count("jwt-secret") == 0)
    {
        spdlog::critical("no jwt secret specified, exiting");
        exit(1);
    }

    if (vm.count("port") == 0)
    {
        spdlog::warn("no port specified, using default port 8000");
    }

    return vm;
}
