#include "client.h"
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sys/socket.h>
#include "tls.h"
#include "storage/tls_keys.h"

bool client::init() {
    struct addrinfo hints = {};
    struct addrinfo *addr_list, *cur;
    struct sockaddr_in *serv_addr = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if ( getaddrinfo("localhost", "3344", &hints, &addr_list ) != 0 ) {
        return false;
    }
    int fd = -1;
    for ( cur = addr_list; cur != nullptr; cur = cur->ai_next ) {
        fd = socket( cur->ai_family, cur->ai_socktype, cur->ai_protocol );
        if ( fd < 0 ) {
            fd = -1;
            continue;
        }
        serv_addr = (struct sockaddr_in *)cur->ai_addr;
        serv_addr->sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
        if ( connect( fd, (struct sockaddr *)serv_addr, cur->ai_addrlen ) != 0 ) {
            close( fd );
            fd = -1;
            continue;
        }
        break;
    }
    if (fd == -1) {
        return false;
    }
    Tls tls;
    tls.set_own_cert(tls_keys::get_client_cert(), tls_keys::get_client_key());
    tls.init(false, false);
    if (tls.handshake(fd) == -1) {
        printf( "FAILED!" );
        return false;
    }
    tls.write(reinterpret_cast<const unsigned char *>("test_string12345"), 15);

    return true;
}
