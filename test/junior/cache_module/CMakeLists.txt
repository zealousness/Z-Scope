cmake_minimum_required(VERSION 3.10)
project(cache_module C)

set(CMAKE_C_STANDARD 99)

include_directories(include)

file(GLOB SOURCES "src/*.c")

add_library(cache_module SHARED ${SOURCES})

# Add an executable for testing
add_executable(cache_test src/cache_core.c) # This is a placeholder, usually a separate test file
target_link_libraries(cache_test cache_module pthread)
