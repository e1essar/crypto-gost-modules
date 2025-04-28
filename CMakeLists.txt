cmake_minimum_required(VERSION 3.10)
project(vpn_proto)
set(CMAKE_CXX_STANDARD 14)
find_package(OpenSSL REQUIRED)
include_directories(include)

add_executable(server src/server.cpp src/kuznyechik.cpp src/magma.cpp)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)

add_executable(client src/client.cpp src/kuznyechik.cpp src/magma.cpp)
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)