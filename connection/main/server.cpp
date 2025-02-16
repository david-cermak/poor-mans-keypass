/*
 * SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <thread>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "esp_log.h"
#include "mbedtls_wrap.hpp"
//#include "test_certs.hpp"

namespace test_certs {
using pem_format = const unsigned char;
extern pem_format cacert_start[] asm("_binary_ca_crt_start");
extern pem_format cacert_end[] asm("_binary_ca_crt_end");
extern pem_format servercert_start[] asm("_binary_srv_crt_start");
extern pem_format servercert_end[] asm("_binary_srv_crt_end");
extern pem_format serverkey_start[] asm("_binary_srv_key_start");
extern pem_format serverkey_end[] asm("_binary_srv_key_end");

enum class type {
    cacert,
    servercert,
    serverkey,
};

#define IF_BUF_TYPE(buf_type)  \
    if (t == type::buf_type) { \
        return idf::mbedtls_cxx::const_buf{buf_type ## _start, buf_type ## _end - buf_type ## _start}; \
    }

static inline idf::mbedtls_cxx::const_buf get_buf(type t)
{
    IF_BUF_TYPE(cacert);
    IF_BUF_TYPE(servercert);
    IF_BUF_TYPE(serverkey);
    return idf::mbedtls_cxx::const_buf{};
}

static inline const char *get_server_cn()
{
    return "espressif.local";
}

}

namespace {
constexpr auto *TAG = "tcp_example";
}

using namespace idf::mbedtls_cxx;
using namespace test_certs;

class SecureLink : public Tls {
public:
    explicit SecureLink() : Tls(), addr("localhost", 3333, AF_INET, SOCK_STREAM) {}
    ~SecureLink() override
    {
        if (client_sock >= 0) {
            ::close(client_sock);
        }
        if (sock >= 0) {
            ::close(sock);
        }
    }
    int send(const unsigned char *buf, size_t len) override
    {
        return ::send(client_sock, buf, len, 0);
    }
    int recv(unsigned char *buf, size_t len) override
    {
        return ::recv(client_sock, buf, len, 0);
    }
    int recv_timeout(unsigned char *buf, size_t len, int timeout) override
    {
        struct timeval tv {
                timeout / 1000, (timeout % 1000 ) * 1000
        };
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);

        int ret = select(client_sock + 1, &read_fds, nullptr, nullptr, timeout == 0 ? nullptr : &tv);
        if (ret == 0) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
        if (ret < 0) {
            if (errno == EINTR) {
                return MBEDTLS_ERR_SSL_WANT_READ;
            }
            return ret;
        }
        return recv(buf, len);
    }
    bool open(bool server_not_client)
    {
        if (!addr) {
            ESP_LOGE(TAG, "Failed to resolve endpoint");
            return false;
        }
        sock = addr.get_sock();
        if (sock < 0) {
            ESP_LOGE(TAG, "Failed to create socket");
            return false;
        }

        if (server_not_client) {
            int err = bind(sock, addr, ai_size);
            if (err < 0) {
                ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
                return false;
            }

            if (listen(sock, 1) < 0) {
                ESP_LOGE(TAG, "Socket listen failed: errno %d", errno);
                return false;
            }

            ESP_LOGI(TAG, "Waiting for a client connection...");
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            client_sock = accept(sock, (struct sockaddr *)&client_addr, &client_len);
            if (client_sock < 0) {
                ESP_LOGE(TAG, "Socket accept failed: errno %d", errno);
                return false;
            }

            ESP_LOGI(TAG, "Client connected.");
        }

        TlsConfig config{};
        config.is_dtls = false;  // No DTLS for TCP
        config.timeout = 10000;

        if (!init(is_server{server_not_client}, do_verify{true}, &config)) {
            return false;
        }

        return handshake() == 0;
    }

private:
    int sock{-1};
    int client_sock{-1};

    struct addr_info {
        struct addrinfo *ai = nullptr;
        explicit addr_info(const char *host, int port, int family, int type)
        {
            struct addrinfo hints {};
            hints.ai_family = family;
            hints.ai_socktype = type;
            hints.ai_protocol = IPPROTO_TCP;
            if (getaddrinfo(host, nullptr, &hints, &ai) < 0) {
                freeaddrinfo(ai);
                ai = nullptr;
            }
            auto *p = (struct sockaddr_in *)ai->ai_addr;
            p->sin_port = htons(port);
        }
        ~addr_info()
        {
            freeaddrinfo(ai);
        }
        explicit operator bool() const
        {
            return ai != nullptr;
        }
        operator sockaddr *() const
        {
            auto *p = (struct sockaddr_in *)ai->ai_addr;
            return (struct sockaddr *)p;
        }

        int get_sock() const
        {
            return socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        }
    } addr;
    const int ai_size{sizeof(struct sockaddr_in)};
};


namespace {

void tls_server()
{
    unsigned char message[128];
    SecureLink server;
    if (!server.set_own_cert(get_buf(type::servercert), get_buf(type::serverkey))) {
        ESP_LOGE(TAG, "Failed to set own cert");
        return;
    }
    if (!server.set_ca_cert(get_buf(type::cacert))) {
        ESP_LOGE(TAG, "Failed to set peer's cert");
        return;
    }
    ESP_LOGI(TAG, "opening...");
    if (!server.open(true)) {

        ESP_LOGE(TAG, "Failed to OPEN! %d", errno);
        return;
    }
    int len = server.read(message, sizeof(message));
    if (len < 0) {
        ESP_LOGE(TAG, "Failed to read!");
        return;
    }
    ESP_LOGI(TAG, "Received from client: %.*s", len, message);
    if (server.write(message, len) < 0) {
        ESP_LOGE(TAG, "Failed to write!");
        return;
    }
    ESP_LOGI(TAG, "Written back");
}

void udp_auth()
{
    std::thread t2(tls_server);
//    std::thread t1(tls_client);
//    t1.join();
    t2.join();
}

} // namespace

#if CONFIG_IDF_TARGET_LINUX
/**
 * Linux target: We're already connected, just run the client
 */
int main()
{
    udp_auth();
    return 0;
}
#else
/**
 * ESP32 chipsets:  Need to initialize system components
 *                  and connect to network
 */

#include "esp_event.h"
#include "esp_netif.h"

extern "C" void app_main()
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    udp_auth();
}
#endif

