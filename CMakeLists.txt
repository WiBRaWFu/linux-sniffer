cmake_minimum_required(VERSION 3.22)
project(sniffer)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_BUILD_TYPE debug)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ncurses
find_package(Curses REQUIRED)
# pcap
set(PCAP_INCLUDE_DIR /usr/include/pcap)
set(PCAP_LIBRARY /usr/lib/x86_64-linux-gnu/libpcap.so.1.10.1)
# cdk
set(CDK_INCLUDE_DIR /usr/include/cdk)
set(CDK_LIBRARY /usr/lib/x86_64-linux-gnu/libcdk.so)

aux_source_directory(src SRC)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR})
add_executable(sniffer ${SRC})

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIR}
    ${CDK_INCLUDE_DIR}
)
target_include_directories(sniffer PRIVATE ${CURSES_INCLUDE_DIR})

target_link_libraries(sniffer ${CURSES_LIBRARIES})
target_link_libraries(sniffer ${PCAP_LIBRARY})
target_link_libraries(sniffer ${CDK_LIBRARY})