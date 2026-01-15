# SPDX-License-Identifier: Unlicense
cmake_minimum_required(VERSION 3.14)

# Main project
project(lab03 VERSION 1.0.0 LANGUAGES C)

# check for libpcap
find_library(PCAP pcap REQUIRED)

# declare options
option(BUILD_SOLUTIONS
  "[INSTRUCTOR ONLY] Build with solutions for testing" OFF)

if(DEFINED PCAP)
  message("-- Found libpcap library!")
endif()

# Set some config options for output directories
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR}/lib)

# add the src subdirectory
add_subdirectory(src)

