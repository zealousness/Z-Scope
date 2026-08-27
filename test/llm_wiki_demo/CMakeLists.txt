cmake_minimum_required(VERSION 3.10)
project(zscope_llm_wiki_demo C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(wiki_demo STATIC
    src/label_store.c
    src/command_runner.c
    src/frame_decoder.c
    src/port_parser.c
    src/callback_registry.c
)

target_include_directories(wiki_demo PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

if (UNIX)
    target_link_libraries(wiki_demo PUBLIC pthread)
endif()
