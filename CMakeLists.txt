cmake_minimum_required (VERSION 3.0)
project (tcpdup)
set (Tutorial_VERSION_MAJOR 1)
set (Tutorial_VERSION_MINOR 0)

SET(EXECUTABLE_OUTPUT_PATH ${tcpdup_SOURCE_DIR}/bin)

SET(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -rdynamic -g -ggdb3 -Wall -Werror")
#SET(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -rdynamic -g -O2 -Wall -Werror")

INCLUDE_DIRECTORIES("include")

link_directories("lib")

AUX_SOURCE_DIRECTORY(src SRC_LIST)

add_library(tcpduplib STATIC ${SRC_LIST})

add_executable (tcpdup tcpdup.c)
add_executable (transfer transfer.c)

target_link_libraries(tcpdup tcpduplib pthread pcap)
target_link_libraries(transfer tcpduplib pthread pcap)

