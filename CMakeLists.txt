cmake_minimum_required(VERSION 3.13.0)
cmake_policy(SET CMP0069 NEW)
project(openexecution VERSION 1.0.1)

# include(CTest)
# enable_testing()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENABLE_LTO "Enable cross language linking time optimization" ON)

if(ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT supported OUTPUT error)

    if(supported)
        message(STATUS "IPO / LTO enabled")
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(STATUS "IPO / LTO not supported: <${error}>")
    endif()
endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
enable_language(Rust)
include(CMakeCargo)

add_executable(openexecution src/main.cpp)
option(BUILD_SHARED_LIBS "build libraries shared" OFF)
option(CURL_ZLIB "use curl with zlib" OFF)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

add_subdirectory(boost-cmake)
target_link_libraries(openexecution PUBLIC Boost::boost)
target_link_libraries(openexecution PUBLIC Boost::program_options)

add_subdirectory(rust_jwt)

if(WIN32)
    target_link_libraries(openexecution PRIVATE rust_jwt ws2_32 userenv)
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
    target_link_libraries(openexecution PRIVATE rust_jwt resolv)
else()
    target_link_libraries(openexecution PRIVATE rust_jwt pthread dl m)
endif()

include(FetchContent)

FetchContent_Declare(rocksdb GIT_REPOSITORY https://github.com/facebook/rocksdb.git
    GIT_TAG v8.0.0)
FetchContent_MakeAvailable(rocksdb)
target_link_libraries(openexecution PRIVATE rocksdb)

FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG db351ffbbadc6c4e9239daaa26e9aefa9f0ec82d)
FetchContent_MakeAvailable(cpr)
target_link_libraries(openexecution PRIVATE cpr::cpr)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
FetchContent_MakeAvailable(json)
target_link_libraries(openexecution PRIVATE nlohmann_json::nlohmann_json)

FetchContent_Declare(spdlog GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.10.0)
FetchContent_MakeAvailable(spdlog)
target_link_libraries(openexecution PRIVATE spdlog::spdlog_header_only)

install(TARGETS openexecution RUNTIME DESTINATION bin)