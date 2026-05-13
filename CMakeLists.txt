cmake_minimum_required(VERSION 3.14)
project(twag_poc C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Dependencies
include(ExternalProject)
include(FetchContent)

# 1. freeDiameter (CMake-based)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/freeDiameter/cmake/Modules/")
set(DISABLE_SCTP ON CACHE BOOL "Disable SCTP in freeDiameter" FORCE)
set(SCTP_INCLUDE_DIR "" CACHE STRING "SCTP Include Dir Fix" FORCE)
add_subdirectory(freeDiameter EXCLUDE_FROM_ALL)

# 2. libgtpv2c (Makefile-based)
ExternalProject_Add(libgtpv2c_proj
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libgtpv2c
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make
    INSTALL_COMMAND ""
)
add_library(gtpv2c SHARED IMPORTED)
set_target_properties(gtpv2c PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libgtpv2c/lib/libgtpv2c.so
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libgtpv2c/include
)
add_dependencies(gtpv2c libgtpv2c_proj)

# 3. libgtpnl (Autotools-based)
ExternalProject_Add(libgtpnl_proj
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libgtpnl
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ./configure
    BUILD_COMMAND make
    INSTALL_COMMAND ""
)
add_library(gtpnl SHARED IMPORTED)
set_target_properties(gtpnl PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/libgtpnl/src/.libs/libgtpnl.so
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libgtpnl/include
)
add_dependencies(gtpnl libgtpnl_proj)

# Core Library (to be linked by both app and tests)
FetchContent_Declare(
  yajson
  GIT_REPOSITORY https://github.com/aloshkarev/yajson.git
  GIT_TAG main
)
set(YAJSON_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAJSON_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(yajson)

add_library(twag_lib STATIC
    src/twag_core.cpp
    src/event_loop.cpp
    src/session_manager.cpp
    src/sta_interface.cpp
    src/s2a_interface.cpp
    src/config_manager.cpp
    src/radius_server.cpp
    src/dhcp_server.cpp
    src/data_plane.cpp
)

target_include_directories(twag_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/freeDiameter/include
    ${CMAKE_CURRENT_BINARY_DIR}/freeDiameter/include
    ${yajson_SOURCE_DIR}/include
)

target_link_libraries(twag_lib PUBLIC
    libfdcore
    libfdproto
    gtpv2c
    gtpnl
    pthread
    resolv
)
add_dependencies(twag_lib dict_nasreq dict_eap dict_dcca)

# TWAG Executable
add_executable(twag src/main.cpp)
target_link_libraries(twag PRIVATE twag_lib)

# Testing
enable_testing()

FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(twag_tests 
    tests/test_session_manager.cpp
    tests/test_s2a_payload.cpp
)
target_link_libraries(twag_tests PRIVATE twag_lib gtest_main)

include(GoogleTest)
gtest_discover_tests(twag_tests)
