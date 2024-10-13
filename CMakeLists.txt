cmake_minimum_required(VERSION 3.22)
project(sniffer)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE debug)

find_package(Curses REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)
aux_source_directory(src SRC)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR})
add_executable(sniffer ${SRC})
target_include_directories(sniffer PRIVATE ${CURSES_INCLUDE_DIR})
target_link_libraries(sniffer ${CURSES_LIBRARIES})