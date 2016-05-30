project(ipproof C)
cmake_minimum_required(VERSION 2.6)

add_executable(ipproof-client src/client.c  src/coot-getopt.h  src/getopt.c  src/global.h  src/pstdint.h  src/shared.c)
add_executable(ipproof-server src/server.c  src/coot-getopt.h  src/getopt.c  src/global.h  src/pstdint.h  src/shared.c)