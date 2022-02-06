#include <iostream>
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "tls.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include "sys/socket.h"
#include "storage/tls_keys.h"
#include "test/client.h"

#define DEBUG_LEVEL 0

static const unsigned char to_decrypt[] = {126, 200, 113, 150, 184, 40, 214, 157, 225, 210, 53, 192, 187, 211, 45, 76, 171, 163, 155, 187, 122, 22, 8, 240, 95, 54, 210, 180, 13, 134, 61, 4, 51, 97, 221, 94, 12, 244, 97, 227, 34, 224, 236, 116, 24, 69, 88, 5, 41, 58, 242, 187, 235, 81, 97, 66, 243, 180, 177, 45, 251, 85, 101, 255, 220, 148, 56, 24, 170, 54, 191, 144, 233, 62, 161, 135, 57, 151, 72, 54, 83, 225, 211, 36, 190, 221, 16, 142, 160, 35, 19, 248, 3, 113, 226, 149, 255, 148, 154, 146, 173, 51, 97, 149, 94, 196, 5, 83, 79, 115, 196, 169, 184, 90, 13, 187, 120, 109, 218, 1, 244, 249, 222, 191, 148, 190, 6, 177, 30, 61, 0, 118, 226, 19, 251, 79, 127, 171, 120, 89, 245, 82, 82, 155, 91, 47, 247, 157, 100, 27, 26, 88, 18, 86, 165, 183, 244, 0, 245, 54, 190, 46, 3, 216, 106, 35, 172, 224, 110, 180, 96, 209, 132, 14, 0, 243, 109, 132, 157, 129, 86, 254, 94, 9, 142, 141, 1, 75, 1, 38, 171, 152, 45, 107, 183, 139, 202, 105, 35, 226, 23, 93, 251, 115, 100, 67, 33, 131, 106, 68, 163, 207, 68, 71, 149, 170, 68, 204, 93, 177, 141, 99, 215, 179, 156, 96, 70, 85, 78, 155, 115, 240, 254, 196, 56, 24, 78, 49, 246, 128, 5, 200, 99, 154, 43, 3, 93, 157, 192, 15, 252, 108, 238, 165, 25, 79};


static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

class Uart_Tls : public Tls {
public:
    int send(const unsigned char *buf, size_t len) override
    {
        for (int i=0; i<len; ++i) {
            int c = fputc(buf[i], stdout);
            if (c == -1) {
                fflush(stdout);
                return i;
            }
        }
        fflush(stdout);
        return len;
    }

    int recv(unsigned char *buf, size_t len) override
    {
        for (int i=0; i<len; ++i) {
            int c = fgetc(stdin);
            if (c == -1) {
                return i;
            }
            buf[i] = c;
        }
        return len;
    }

};

int main() {
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];

//    client c;
//    c.init();
//    return 0;
    Uart_Tls s;
    s.set_mater_key(tls_keys::get_master_key());
    s.set_own_cert(tls_keys::get_server_cert(), tls_keys::get_server_key());
    s.set_ca_cert(tls_keys::get_ca_cert());
    s.init(true, true);
    auto output = std::make_pair(result, sizeof(result));
    auto input = std::make_pair((unsigned char*)to_decrypt, sizeof(to_decrypt));
    size_t olen = s.decrypt(input, output);
    printf("\n!!!%.*s!!!\n", (int)olen, result);
    if (s.handshake(0) == -1) {
        printf( "FAILED!" );
        return 1;
    }
    printf( "OKAY\n" );
    return 0;

    struct addrinfo hints = {};
    struct addrinfo *addr_list, *cur;
    struct sockaddr_in *serv_addr = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if ( getaddrinfo("0.0.0.0", "3344", &hints, &addr_list ) != 0 ) {
        return 1;
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
        if ( bind( fd, (struct sockaddr *)serv_addr, cur->ai_addrlen ) != 0 ) {
            close( fd );
            fd = -1;
            continue;
        }
        if ( listen( fd, 4 ) != 0 ) {
            close( fd );
            fd = -1;
            continue;
        }
        break;
    }
    if (fd == -1) {
        return 1;
    }
    printf( "  . Waiting for a remote connection ...\n" );
    struct sockaddr_in client_addr = {};
    auto n = (socklen_t) sizeof( client_addr );
    int client = (int) accept( fd, (struct sockaddr *) &client_addr, &n );
    printf( "  . Performing the SSL/TLS handshake..." );
    if (s.handshake(client) == -1) {
        printf( "FAILED!" );
        return 1;
    }
    printf( "OKAY\n" );
    uint8_t buf[100];
    while (true) {
        int ret = s.read( buf, sizeof(buf) );
        if (ret > 5) {
            printf( "%*s\n", ret, buf );
            if (strncmp((char*)buf, "end", 3) == 0) {
                break;
            }
            s.write((unsigned char *)"cool!\n", 6);
        }
    }
    return 0;
}

#if ESP_PLATFORM
#include "nvs_flash.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "esp_event.h"

extern "C" void app_main()
{
    printf("Starting fgetc\n");
    int c;
    while ((c = fgetc(stdin)) == -1) {
        vTaskDelay(1);
    }

    printf("%x\n", c);

//    ESP_ERROR_CHECK(nvs_flash_init());
//    ESP_ERROR_CHECK(esp_netif_init());
//    ESP_ERROR_CHECK(esp_event_loop_create_default());
//
//    ESP_ERROR_CHECK(example_connect());
    main();
}
#endif