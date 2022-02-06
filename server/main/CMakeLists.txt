
idf_component_register(SRCS         main.cpp
                                    tls.cpp
                                    ${CMAKE_BINARY_DIR}/keys_tls.cpp
                                    test/client.cpp
        INCLUDE_DIRS . include)
#return()

#project(server)
#set(MbedTLS_DIR $ENV{MbedTLS_DIR})
#
##set(CMAKE_CXX_STANDARD 14)
#find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)
#
#find_package(MbedTLS)
#
##add_executable(server
##        main.cpp
##        tls.cpp
##        ${CMAKE_BINARY_DIR}/keys_tls.cpp
##        test/client.cpp)
#target_link_libraries(server
#        PUBLIC MbedTLS::mbedtls)
##        MbedTLS::mbedcrypto
##        MbedTLS::mbedx509)