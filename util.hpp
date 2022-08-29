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

        ("help,h", "produce help message")                                                                                                                      // help message
        ("version,v", "print version")                                                                                                                          // version message
        ("log-level", boost::program_options::value<std::string>(), "verbosity of the program. Possible values: TRACE DEBUG INFO WARN ERROR CRITICAL")          // log level
        ("port,p", boost::program_options::value<int>(), "port to listen on")                                                                                   // port to listen on
        ("listen-addr,addr", boost::program_options::value<std::string>(), "address to listen on for json-rpc")                                                 // listen addr
        ("jwt-secret,jwt", boost::program_options::value<std::string>(), "filepath for the jwt secret")                                                         // jwt-secret
        ("fee_override_chance", boost::program_options::value<double>(), "percentage in decimal form that a clients fee recipient gets replaced with your own") // fee_override_chance
        ("fee_override_address", boost::program_options::value<std::string>(), "address to replace the fee recipient with")                                     // fee_override_address
        ("unauth-node, un", boost::program_options::value<std::string>(), "unauthenticated node url (could be something like infura)")                          // unauth-node
        ("node,n", boost::program_options::value<std::string>(), "the ip of the \"canonical\" node");                                                           // canonical node

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
        std::cout << "openexecution version 1.0.1\n";
        std::cout << "Compiled with " << BOOST_COMPILER << std::endl;
        std::cout << "Made with love by tennis ;) <3" << std::endl;
        exit(0);
    }

    // check that if fee_override_chance is set, fee_override_address is also set
    if (vm.count("fee_override_chance") && !vm.count("fee_override_address"))
    {
        spdlog::critical("fee_override_chance is set, but fee_override_address is not set");
        exit(1);
    }

    if (vm.count("node") == 0)
    {
        spdlog::critical("no canonical node specified, exiting");
        exit(1);
    }

    if (vm.count("unauth-node") == 0)
    {
        spdlog::critical("no unauthenticated node specified, exiting");
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

    if (vm.count("log-level"))
    {
        std::string log_level = vm["log-level"].as<std::string>();
        if (log_level == "TRACE")
        {
            spdlog::set_level(spdlog::level::trace);
        }
        else if (log_level == "DEBUG")
        {
            spdlog::set_level(spdlog::level::debug);
        }
        else if (log_level == "INFO")
        {
            spdlog::set_level(spdlog::level::info);
        }
        else if (log_level == "WARN")
        {
            spdlog::set_level(spdlog::level::warn);
        }
        else if (log_level == "ERROR")
        {
            spdlog::set_level(spdlog::level::err);
        }
        else if (log_level == "CRITICAL")
        {
            spdlog::set_level(spdlog::level::critical);
        }
        else
        {
            spdlog::error("Invalid log level: {}", log_level);
            exit(1);
        }
    }
    else
    {
        spdlog::set_level(spdlog::level::info);
    }

    return vm;
}
