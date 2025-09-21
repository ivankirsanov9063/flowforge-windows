cmake_minimum_required(VERSION 3.18)

project(ClientCore LANGUAGES CXX)

# Выравниваем ABI Boost под системные .so (в т.ч. libboost_log.so)
add_compile_definitions(BOOST_ALL_DYN_LINK)

add_library(ClientCore SHARED
        Client.cpp
        Network.cpp
        FirewallRules.cpp
        NetWatcher.cpp
        DNS.cpp
        NetworkRollback.cpp

        ${CMAKE_SOURCE_DIR}/Core/PluginWrapper.cpp
        ${CMAKE_SOURCE_DIR}/Core/TUN.cpp
        ${CMAKE_SOURCE_DIR}/Core/Logger.cpp
        ${CMAKE_SOURCE_DIR}/Core/Config.cpp
)

target_compile_definitions(ClientCore PRIVATE _WIN32_WINNT=0x0602 BOOST_USE_WINAPI_VERSION=0x0602)

target_compile_features(ClientCore PRIVATE cxx_std_23)
target_include_directories(ClientCore PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED COMPONENTS log log_setup thread filesystem regex json)
find_package(Threads REQUIRED)

# Важно: log_setup раньше log
target_link_libraries(ClientCore
        PRIVATE
        Boost::log_setup
        Boost::log
        Boost::thread
        Boost::filesystem
        Boost::regex
        Boost::json
        Threads::Threads
)

target_link_libraries(ClientCore PRIVATE Ws2_32 Iphlpapi)

install(TARGETS ClientCore RUNTIME DESTINATION bin)
