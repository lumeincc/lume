# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.28)

project(lume VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(LUME_BUILD_TESTS "Build the test suites" ON)
option(LUME_COVERAGE "Instrument the build for coverage" OFF)
option(LUME_BUILD_FUZZERS "Build the libFuzzer targets, Clang only" OFF)
set(LUME_SANITIZERS "" CACHE STRING "Sanitizers to enable, for example address;undefined")

include(cmake/LumeCompilerOptions.cmake)

if(LUME_BUILD_TESTS)
    enable_testing()
endif()

add_subdirectory(core)
