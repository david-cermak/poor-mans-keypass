#include "mbedtls/pk.h"
#include "tls.h"
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include "sys/socket.h"
#include "storage/tls_keys.h"
#include "test/client.h"

#ifdef ESP_PLATFORM
#include "nvs_flash.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "esp_event.h"
#include "esp_vfs.h"
#include "esp_vfs_dev.h"
#include "driver/uart.h"
#include "esp_log.h"

class Uart_Tls : public Tls {
public:
  int send(const unsigned char *buf, size_t len) override
  {
    return uart_write_bytes(UART_NUM_1, buf, len);
  }

  int recv(unsigned char *buf, size_t len) override
  {
    size_t length = 0;
    int real_len = uart_read_bytes(UART_NUM_1, buf, 1, portMAX_DELAY);
    uart_get_buffered_data_len(UART_NUM_1, &length);
    if (length > len-1) {
      length = len-1;
    }
    real_len += uart_read_bytes(UART_NUM_1, buf+1, length, portMAX_DELAY);
    return real_len;
  }

};
#else
class Uart_Tls : public Tls
{ };
#endif

int create_server()
{
    struct addrinfo hints = {};
    struct addrinfo *addr_list, *cur;
    struct sockaddr_in *serv_addr = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if ( getaddrinfo("0.0.0.0", "3344", &hints, &addr_list ) != 0 ) {
        return -1;
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
        return -1;
    }
    printf( "  . Waiting for a remote connection ...\n" );
    struct sockaddr_in client_addr = {};
    auto n = (socklen_t) sizeof( client_addr );
    int client = (int) accept( fd, (struct sockaddr *) &client_addr, &n );
    printf( "  . Performing the SSL/TLS handshake..." );
    return client;
}

int main() {
#ifndef ESP_PLATFORM
    client c;
    c.init();
    return 0;
#endif
    Uart_Tls s;
    unsigned char buf [512] = {0x55};
    s.set_mater_key(tls_keys::get_master_key());
    s.set_own_cert(tls_keys::get_server_cert(), tls_keys::get_server_key());
    s.set_ca_cert(tls_keys::get_ca_cert());
    s.init(true, true);
    int client = 0; // = create_server();
    if (s.handshake(client) == -1) {
        printf( "FAILED!" );
        return 1;
    }

    printf( "OKAY\n" );
    unsigned char result[MBEDTLS_MPI_MAX_SIZE];
    while (true) {
        size_t size = s.read( buf, sizeof(buf) );
        if (size > 5) {
            printf("Data to decrypt:");
            for (int i=0; i<size; ++i)
              printf("0x%0x, ", buf[i]);
            printf("\n");
            auto output = std::make_pair(result, sizeof(result));
            auto input = std::make_pair((unsigned char*)buf, size);
            size_t olen = s.decrypt(input, output);
            printf("Decrypted:[%.*s]\n", (int)olen, result);
            s.write((unsigned char *)result, olen);
        }
    }
    return 0;
}

#if ESP_PLATFORM

static void uart1_init(void)
{
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_APB,
    };
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM_1, 2048, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(UART_NUM_1, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM_1, 1, 3, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
}

extern "C" void app_main()
{
    uart1_init();
    main();
}

#endif