cmake_minimum_required(VERSION 3.16)
project(StatefulFirewall
    VERSION 1.0.0
    DESCRIPTION "Stateful Application-Layer Firewall & Intrusion Filter"
    LANGUAGES CXX
)

# Enforce C++17 Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configure Binary Output Directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Compilation Flags (-Wall, -Wextra, -pedantic, -O3)
add_compile_options(-Wall -Wextra -pedantic -O3)

# Threading Library
find_package(Threads REQUIRED)

# Netfilter Queue Library Detection (Linux Target)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(NFQ QUIET libnetfilter_queue)
    pkg_check_modules(NFNL QUIET libnfnetlink)
endif()

find_library(NETFILTER_QUEUE_LIB NAMES netfilter_queue)
find_library(NFNETLINK_LIB NAMES nfnetlink)

set(NETFILTER_LINK_LIBS "")
if(NFQ_FOUND)
    list(APPEND NETFILTER_LINK_LIBS ${NFQ_LIBRARIES})
    include_directories(${NFQ_INCLUDE_DIRS})
    message(STATUS "Found libnetfilter_queue via pkg-config: ${NFQ_LIBRARIES}")
elseif(NETFILTER_QUEUE_LIB)
    list(APPEND NETFILTER_LINK_LIBS ${NETFILTER_QUEUE_LIB})
    message(STATUS "Found libnetfilter_queue via find_library: ${NETFILTER_QUEUE_LIB}")
else()
    message(STATUS "libnetfilter_queue not detected on build host. Target is Linux (libnetfilter-queue-dev).")
endif()

if(NFNL_FOUND)
    list(APPEND NETFILTER_LINK_LIBS ${NFNL_LIBRARIES})
    include_directories(${NFNL_INCLUDE_DIRS})
elseif(NFNETLINK_LIB)
    list(APPEND NETFILTER_LINK_LIBS ${NFNETLINK_LIB})
endif()

# Core Firewall Static Library
add_library(firewall_core STATIC
    src/Protocol.cpp
    src/Logger.cpp
    src/ConntrackTable.cpp
    src/Inspector.cpp
    src/Interceptor.cpp
    src/FirewallDaemon.cpp
)

target_include_directories(firewall_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(firewall_core PUBLIC
    Threads::Threads
    ${NETFILTER_LINK_LIBS}
)

# Main Executable: stateful_firewall
add_executable(stateful_firewall
    src/main.cpp
)

target_link_libraries(stateful_firewall PRIVATE
    firewall_core
)

# Test Suite Executable: firewall_tests
add_executable(firewall_tests
    tests/test_firewall.cpp
)

target_link_libraries(firewall_tests PRIVATE
    firewall_core
)

enable_testing()
add_test(NAME FirewallUnitAndIntegrationTests COMMAND firewall_tests)
