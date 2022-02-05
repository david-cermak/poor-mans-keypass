cmake_minimum_required(VERSION 3.16)
project(server)
set(MbedTLS_DIR $ENV{MbedTLS_DIR})
set(CA_CRT $ENV{CA_CRT})
string(REPLACE "*" "\\n" CA_CRT ${CA_CRT})
set(SERVER_KEY  $ENV{SERVER_KEY})
string(REPLACE "*" "\\n" SERVER_KEY ${SERVER_KEY})
set(SERVER_CRT  $ENV{SERVER_CRT})
string(REPLACE "*" "\\n" SERVER_CRT ${SERVER_CRT})
set(MASTER_KEY  $ENV{MASTER_KEY})
string(REPLACE "*" "\\n" MASTER_KEY ${MASTER_KEY})
set(CLIENT_KEY  $ENV{CLIENT_KEY})
string(REPLACE "*" "\\n" CLIENT_KEY ${CLIENT_KEY})
set(CLIENT_CRT  $ENV{CLIENT_CRT})
string(REPLACE "*" "\\n" CLIENT_CRT ${CLIENT_CRT})

configure_file(storage/tls.cpp.in keys_tls.cpp)
set(CMAKE_CXX_STANDARD 14)
find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)
include_directories(. include)
find_package(MbedTLS)

add_executable(server
        main.cpp
        tls.cpp
        ${CMAKE_BINARY_DIR}/keys_tls.cpp
        test/client.cpp)
target_link_libraries(server
        PUBLIC MbedTLS::mbedtls)
#        MbedTLS::mbedcrypto
#        MbedTLS::mbedx509)