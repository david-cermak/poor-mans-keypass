# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)

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

configure_file(main/storage/tls.cpp.in keys_tls.cpp)

if (${ESP_PLATFORM} MATCHES 1)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_server)
else()
project(server)

macro(idf_component_register)
    foreach(arg ${ARGN})
        if (${arg} MATCHES SRCS)
            set(action SRCS)
        elseif(${arg} MATCHES INCLUDE_DIRS)
            set(action INCLUDE_DIRS)
        elseif(${action} MATCHES "SRCS")
            message("SRC +++ ${arg}")
            set(ARG_SRCS ${ARG_SRCS} "${arg}")
        elseif(${action} MATCHES INCLUDE_DIRS)
            message("INC +++ ${arg}")
            set(ARG_INCLUDE_DIRS ${ARG_INCLUDE_DIRS} "${arg}")
        endif()
        message("arg---${arg}")
    endforeach(arg)

add_executable(server ${ARG_SRCS})
include_directories(${ARG_INCLUDE_DIRS})

set(MbedTLS_DIR $ENV{MbedTLS_DIR})
find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)
find_package(MbedTLS)
target_link_libraries(server
        PUBLIC MbedTLS::mbedtls)
#        MbedTLS::mbedcrypto
#        MbedTLS::mbedx509)
endmacro()

add_subdirectory(main)
endif()
