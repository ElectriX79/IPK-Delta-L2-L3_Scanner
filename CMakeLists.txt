cmake_minimum_required(VERSION 4.1)
project(IPK C)

set(CMAKE_C_STANDARD 11)

add_executable(IPK
        src/main.c)

target_include_directories(IPK PRIVATE include)