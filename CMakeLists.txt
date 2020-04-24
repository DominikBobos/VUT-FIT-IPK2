cmake_minimum_required(VERSION 3.15)
project(VUT_FIT_IPK2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -pedantic -Wall -Wextra -lpcap")
include_directories(.)

add_executable(VUT_FIT_IPK2
        ipk-sniffer.c
        Makefile)
