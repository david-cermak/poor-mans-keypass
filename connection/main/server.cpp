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
#include "driver/uart.h"
#include "esp_check.h"

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
constexpr auto *TAG = "tls_server_over_uart";
}

using namespace idf::mbedtls_cxx;
using namespace test_certs;

class SecureLink: public Tls {
public:
    explicit SecureLink(uart_port_t port, int tx, int rx) : Tls(), uart(port, tx, rx) {}
    ~SecureLink() = default;
    int send(const unsigned char *buf, size_t len) override
    {
        printf("sending %d bytes\n", len);
        vTaskDelay(pdMS_TO_TICKS(100));
//        ESP_LOG_BUFFER_HEXDUMP("send", buf, len, ESP_LOG_INFO);
        return uart_write_bytes(uart.port_, buf, len);
    }

    int recv(unsigned char *buf, size_t len) override
    {
        // stream read
        int l = uart.recv(buf, len, 100);
//        vTaskDelay(pdMS_TO_TICKS(100));
        if (l>0) {
            printf("received %d bytes\n", l);
//            ESP_HEXDUMP(TAG, buf, l);
        }
        return l;
    }

    int recv_timeout(unsigned char *buf, size_t len, int timeout) override
    {
        // dgram read
        return uart.recv_dgram(buf, len, timeout);
    }

    bool listen() // open as server
    {
        return open(true);
    }

    bool connect() // open as client
    {
        return open(false);
    }

private:
    bool open(bool server_not_client)
    {
        if (uart.init() != ESP_OK) {
            return false;
        }
//        while (!uart.debounce(server_not_client)) {
//            printf("debouncing...\n");
//            usleep(10000);
//        }
        TlsConfig config{};
        config.is_dtls = false;
        config.timeout = 10000;
        if (server_not_client) {
            const unsigned char client_id[] = "Client1";
            config.client_id = std::make_pair(client_id, sizeof(client_id));
        }
        if (!init(is_server{server_not_client}, do_verify{true}, &config)) {
            return false;
        }

        return handshake() == 0;
    }

    /**
     * RAII wrapper of UART
     */
    struct uart_info {
        uart_port_t port_;
        QueueHandle_t queue_{};
        int tx_, rx_;

        // used for datagrams
        bool header_{true};
        int in_payload_{0};
        int payload_len_{0};
        uint8_t payload_[1600] {};

        explicit uart_info(uart_port_t port, int tx, int rx): port_(port), tx_(tx), rx_(rx)
        {
        }
        esp_err_t init()
        {
            uart_config_t uart_config = {};
            uart_config.baud_rate = 115200;
            uart_config.data_bits = UART_DATA_8_BITS;
            uart_config.parity    = UART_PARITY_DISABLE;
            uart_config.stop_bits = UART_STOP_BITS_1;
            uart_config.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
            uart_config.source_clk = UART_SCLK_DEFAULT;
            ESP_RETURN_ON_ERROR(uart_driver_install(port_, 4096, 0, 1, &queue_, 0), TAG, "Failed to install UART");
            ESP_RETURN_ON_ERROR(uart_param_config(port_, &uart_config), TAG, "Failed to set params");
            ESP_RETURN_ON_ERROR(uart_set_pin(port_, tx_, rx_, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE), TAG, "Failed to set UART pins");
            ESP_RETURN_ON_ERROR(uart_set_rx_timeout(port_, 10), TAG, "Failed to set UART Rx timeout");
            return ESP_OK;
        }
        ~uart_info()
        {
            uart_driver_delete(port_);
        }
        bool debounce(bool server)
        {
            uint8_t data = 0;
            if (server) {
                while (uart_read_bytes(port_, &data, 1, 0) != 0) {
                    if (data == 0x55) {
                        uart_write_bytes(port_, &data, 1);
                        return true;
                    }
                }
                return false;
            }
            data = 0x55;
            uart_write_bytes(port_, &data, 1);
            data = 0;
            uart_read_bytes(port_, &data, 1, pdMS_TO_TICKS(1000));
            if (data != 0x55) {
                uart_flush_input(port_);
                return false;
            }
            return true;
        }

        int recv(unsigned char *buf, size_t size, int timeout) // this is for stream transport
        {
            int len = uart_read_bytes(port_, buf, size, pdMS_TO_TICKS(timeout));
            if (len == 0) {
                return MBEDTLS_ERR_SSL_WANT_READ;
            }
            return len;
        }

        int recv_dgram(unsigned char *buf, size_t size, int timeout) // this is for datagrams
        {
            uart_event_t event = {};
            size_t length;
            uart_get_buffered_data_len(port_, &length);
            if (length == 0) {
                xQueueReceive(queue_, &event, pdMS_TO_TICKS(timeout));
            }
            uart_get_buffered_data_len(port_, &length);
            if (length == 0) {
                return MBEDTLS_ERR_SSL_WANT_READ;
            }
            if (header_) {
                if (length >= 2) {
                    uart_read_bytes(port_, &payload_len_, 2, 0);
                    header_ = false;
                    length -= 2;
                }
            }
            if (!header_ && length > 0) {
                int to_read = payload_len_ - in_payload_;
                int l = uart_read_bytes(port_, &payload_[in_payload_], to_read, 0);
                in_payload_ += l;
                if (payload_len_ == in_payload_) {
                    header_ = true;
                    memcpy(buf, payload_, payload_len_);
                    in_payload_ = 0;
                    return payload_len_;
                }
            }
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
    } uart;
};

namespace {

void tls_server()
{
    unsigned char message[128]; // = "Hello, world!";
    SecureLink server(UART_NUM_1, 4, 5);
    if (!server.set_own_cert(get_buf(type::servercert), get_buf(type::serverkey))) {
        ESP_LOGE(TAG, "Failed to set own cert");
        return;
    }
    if (!server.set_ca_cert(get_buf(type::cacert))) {
        ESP_LOGE(TAG, "Failed to set peer's cert");
        return;
    }
    ESP_LOGI(TAG, "opening...");
    if (!server.listen()) {

        ESP_LOGE(TAG, "Failed to OPEN! %d", errno);
        return;
    }
//    int len = 15;
//    server.write((uint8_t*)"\n", 1);
    ESP_LOGI(TAG, "Connection is opened");
    vTaskDelay(pdMS_TO_TICKS(1000));
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

