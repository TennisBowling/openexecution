cmake_minimum_required(VERSION 3.0.0)
project(openexecution VERSION 0.1.0)

cmake_policy(SET CMP0074 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0074 NEW)

# include(CTest)
# enable_testing()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(openexecution main.cpp)

option(BUILD_SHARED_LIBS "build libraries shared" OFF)
option(CURL_ZLIB "use curl with zlib" OFF)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

add_subdirectory(boost-cmake)
target_link_libraries(openexecution PUBLIC Boost::boost)
target_link_libraries(openexecution PUBLIC Boost::program_options)

include(FetchContent)
FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG db351ffbbadc6c4e9239daaa26e9aefa9f0ec82d)
FetchContent_MakeAvailable(cpr)
target_link_libraries(openexecution PUBLIC cpr::cpr)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.10.5/json.tar.xz)
FetchContent_MakeAvailable(json)
target_link_libraries(openexecution PUBLIC nlohmann_json::nlohmann_json)

FetchContent_Declare(spdlog GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.10.0)
FetchContent_MakeAvailable(spdlog)
target_link_libraries(openexecution PUBLIC spdlog::spdlog_header_only)

# set(PostgreSQL_ROOT "C:\\Program Files\\PostgreSQL\\14")
add_subdirectory(libpqxx build-pqxx)
target_link_libraries(openexecution PUBLIC pqxx)

install(TARGETS openexecution RUNTIME DESTINATION bin)