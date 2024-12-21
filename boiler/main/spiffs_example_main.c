/* SPIFFS filesystem example.
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include "esp_err.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_wifi.h"
#include "esp_sleep.h"
#include "nvs_flash.h"
#include "esp_sleep.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#include <sys/socket.h>

RTC_DATA_ATTR static uint16_t temp[10] = { 0 };
RTC_DATA_ATTR static int status = 0;
#define GPIO_OUT 33
#define LED_OUT 32
RTC_DATA_ATTR static int boot_count = 0;

typedef struct interval {
    uint16_t from;
    uint16_t to;
} interval_t;

#define SOLAR 0
#define OVERRIDE 1
#define EVENING  2
#define NIGHT    3

//#define SUMMER_TIME 0
#define SUMMER_TIME 1

RTC_DATA_ATTR static uint16_t temp_low = 28;
RTC_DATA_ATTR static uint16_t temps[] = { 35, 30, 20, 30 };
//RTC_DATA_ATTR static uint16_t temps[] = { 20, 30, 35, 40 };
//RTC_DATA_ATTR static interval_t intervals[] =  {  { 700, 1800 },
//                                                  { 1530, 1600},
//                                                  { 2100, 2230},
//                                                  { 400, 500} };
RTC_DATA_ATTR static interval_t intervals[] =  {  { 430, 530 },
                                                  { 1400, 1600},
                                                  { 600, 1800},
                                                  { 1900, 2000} };

static const char *TAG = "example";
static EventGroupHandle_t s_wifi_event_group;
static void event_handler(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG,"connect to the AP fail");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, 1);
    }
}

#define I2C_MASTER_SCL_IO           4      /*!< GPIO number used for I2C master clock */
#define I2C_MASTER_SDA_IO           5      /*!< GPIO number used for I2C master data  */
#define I2C_MASTER_NUM              0                          /*!< I2C master i2c port number, the number of i2c peripheral interfaces available will depend on the chip */
#define I2C_MASTER_FREQ_HZ          400000                     /*!< I2C master clock frequency */
#define I2C_MASTER_TX_BUF_DISABLE   0                          /*!< I2C master doesn't need buffer */
#define I2C_MASTER_RX_BUF_DISABLE   0                          /*!< I2C master doesn't need buffer */
#define I2C_MASTER_TIMEOUT_MS       1000

/**
 * @brief i2c master initialization
 */
static esp_err_t i2c_master_init(void)
{
    int i2c_master_port = I2C_MASTER_NUM;

    i2c_config_t conf = {
            .mode = I2C_MODE_MASTER,
            .sda_io_num = I2C_MASTER_SDA_IO,
            .scl_io_num = I2C_MASTER_SCL_IO,
            .sda_pullup_en = GPIO_PULLUP_ENABLE,
            .scl_pullup_en = GPIO_PULLUP_ENABLE,
            .master.clk_speed = I2C_MASTER_FREQ_HZ,
    };

    i2c_param_config(i2c_master_port, &conf);

    return i2c_driver_install(i2c_master_port, conf.mode, I2C_MASTER_RX_BUF_DISABLE, I2C_MASTER_TX_BUF_DISABLE, 0);
}


#define PORT 3333

static const esp_vfs_spiffs_conf_t spiffs_conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
};


static void init_spiffs()
{
    ESP_LOGI(TAG, "Initializing SPIFFS");

    esp_err_t ret = esp_vfs_spiffs_register(&spiffs_conf);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }
    size_t total = 0, used = 0;
    ret = esp_spiffs_info(spiffs_conf.partition_label, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s). Formatting...", esp_err_to_name(ret));
        esp_spiffs_format(spiffs_conf.partition_label);
        return;
    } else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }

    if (used > total) {
        ESP_LOGW(TAG, "Number of used bytes cannot be larger than total. Performing SPIFFS_check().");
        ret = esp_spiffs_check(spiffs_conf.partition_label);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "SPIFFS_check() failed (%s)", esp_err_to_name(ret));
            return;
        } else {
            ESP_LOGI(TAG, "SPIFFS_check() successful");
        }
    }
}



void try_to_connect()
{
    uint32_t data;
    char host_ip[] = "192.168.4.2";

    struct sockaddr_in dest_addr;
    inet_pton(AF_INET, host_ip, &dest_addr.sin_addr);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    int sock =  socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        return;
    }
    ESP_LOGI(TAG, "Socket created, connecting to %s:%d", host_ip, PORT);

    int err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "Socket unable to connect: errno %d", errno);
        return;
    }
    ESP_LOGI(TAG, "Successfully connected");
    data = 0;
    int len = recv(sock, &data, 4, 0);
    if (len == 4) {
        ESP_LOGI(TAG, "DATA: %d %x", (int)data, (int)data);
        if (data == 0x1111) {
            init_spiffs();
            unlink("/spiffs/foo.txt");
            FILE *f = fopen("/spiffs/foo.txt", "a");
            fclose(f);
            esp_vfs_spiffs_unregister(spiffs_conf.partition_label);
        } else if (data == 0x1112) {
            gpio_hold_dis(GPIO_OUT);
            while (1) {
                gpio_set_level(GPIO_OUT, 0);
                vTaskDelay(pdMS_TO_TICKS(5000));
                gpio_set_level(GPIO_OUT, 1);
                vTaskDelay(pdMS_TO_TICKS(10000));
            }
        } else if (data >= 0x1200 && data < 0x1300) {
            // Read ODD
            uint16_t index = data;
            data = 12345;
            if (index == 0x1200) {
                data = temp_low;
            } else if (index >= 0x1210 && index < 0x1215) {
                data = temps[index-0x1210];
            } else if (index >= 0x1220 && index < 0x1225) {
                data = intervals[index-0x1220].from;
            } else if (index >= 0x1230 && index < 0x1235) {
                data = intervals[index-0x1230].to;
            }
            len = send(sock, &data, 4, 0);
            if (len <= 0) {
                ESP_LOGE(TAG, "Failed to write: errno %d", errno);
                return;
            }
        } else if (data >= 0x1300 && data < 0x2000) {
            // Write ODD
            uint16_t index = data;
            data = 12345;
            len = recv(sock, &data, 4, 0);
            if (len <= 0) {
                ESP_LOGE(TAG, "Failed to write: errno %d", errno);
                return;
            }
            if (index == 0x1300) {
                temp_low = data;
            } else if (index >= 0x1310 && index < 0x1315) {
                temps[index-0x1310] = data;
            } else if (index >= 0x1320 && index < 0x1325) {
                intervals[index-0x1320].from = data;
            } else if (index >= 0x1330 && index < 0x1335) {
                intervals[index-0x1330].to = data;
            }
        } else if (data == 0x2222) {
            init_spiffs();
            ESP_LOGI(TAG, "Reading file");
            FILE* f = fopen("/spiffs/foo.txt", "r");
            if (f == NULL) {
                ESP_LOGE(TAG, "Failed to open file for reading");
                return;
            }
            uint8_t data[2];
            int c1, c2;
            c1 = fgetc(f);
            c2 = fgetc(f);
            while (c1 >= 0 && c2 >= 0) {
                printf("%02x %02x", c1, c2);
                data[0] = c1;
                data[1] = c2;
                int len = send(sock, data, 2, 0);
                if (len <= 0) {
                    break;
                }
                c1 = fgetc(f);
                c2 = fgetc(f);
            }
            data[0] = 0xFF;
            data[1] = 0xFF;
            len = send(sock, data, 2, 0);
            if (len <= 0) {
                return;
            }
            printf("\n");
            fclose(f);
            esp_vfs_spiffs_unregister(spiffs_conf.partition_label);

        } else {
            struct tm referenceTime = {0};
            referenceTime.tm_year = 2024 - 1900;
            referenceTime.tm_mon = 0;   // January
            referenceTime.tm_mday = 1;  // 1st day
            referenceTime.tm_hour = SUMMER_TIME;  // 00 hours
            referenceTime.tm_min = 0;   // 00 minutes
            referenceTime.tm_sec = 0;   // 00 seconds
            long long secondsSinceReference = data;
            // Calculate the new time based on the given seconds
            struct tm newTime = referenceTime;
            time_t newTimeT = mktime(&newTime) + secondsSinceReference;
            struct timeval newTimeval = {};
            newTimeval.tv_sec = newTimeT;

            settimeofday(&newTimeval, NULL);
            // Convert the new time to a string for printing
            char timeString[30];
            strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", gmtime(&newTimeT));

            // Print the result
            printf("New time based on %lld seconds since January 1, 2024: %s UTC\n", secondsSinceReference, timeString);

        }
    }
    close(sock);
}


static void try_wifi()
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));
    wifi_config_t wifi_config = {
            .sta = {
                    .ssid = "DavidsAP",
                    .password = "DavidsAPPassword",
            },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );
    ESP_LOGI(TAG, "wifi_init_sta finished.");
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,1,pdTRUE,pdTRUE, pdMS_TO_TICKS(60000));
    if (bits & 1) {
        ESP_LOGI(TAG, "connected!");
        try_to_connect();
        esp_wifi_disconnect();
    }

}


uint16_t get_temp()
{
    uint8_t data[2];
    uint16_t temperature = 0xFFFF;
    esp_err_t err = i2c_master_read_from_device(I2C_MASTER_NUM, 0x4f, data, 2, I2C_MASTER_TIMEOUT_MS / portTICK_PERIOD_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to read!");
    }
    temperature = data[1] + 256 * data[0];
    temperature = temperature >> 5;
    ESP_LOGI(TAG, "temp = %f", temperature/8.0);
    return temperature;
}

void blink_task()
{
    gpio_hold_dis(LED_OUT);
    while (1) {
        gpio_set_level(LED_OUT, 0);
        vTaskDelay(pdMS_TO_TICKS(500));
        gpio_set_level(LED_OUT, 1);
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    vTaskDelete(NULL);
}

void app_main(void)
{

    gpio_config_t io_conf = {
            .intr_type = GPIO_INTR_DISABLE,
            .mode = GPIO_MODE_OUTPUT,
            .pin_bit_mask = BIT64(GPIO_OUT) | BIT64(LED_OUT),
    };
    gpio_config(&io_conf);
    gpio_hold_dis(LED_OUT);
    gpio_set_level(LED_OUT, 0);
    gpio_hold_en(LED_OUT);
    gpio_deep_sleep_hold_en();


    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    // Is time set? If not, tm_year will be (1970 - 1900).

    if (timeinfo.tm_year < (2016 - 1900)) {
        status = 0;
        gpio_hold_dis(GPIO_OUT);
        gpio_set_level(GPIO_OUT, 0);
        gpio_hold_en(GPIO_OUT);
        gpio_deep_sleep_hold_en();
        ESP_LOGI(TAG, "Time is not set yet. Connecting to WiFi and getting time over NTP.");
        xTaskCreate(blink_task, "blink", 1024, NULL, 5, NULL);
        try_wifi();
        status = 0;
        esp_deep_sleep(1000000LL); // sleep for one second
//        vTaskCreate
    }
    // now we know that the time is set!
    int hours = timeinfo.tm_hour*100 + timeinfo.tm_min;
    ESP_LOGE(TAG, "Hours: %d", timeinfo.tm_hour*100 + timeinfo.tm_min);


    ESP_ERROR_CHECK(i2c_master_init());
    uint16_t t1 = get_temp();
    uint16_t t2 = get_temp();
    while (abs(t1 -t2) > 8) {
        t1 = t2;
        t2 = get_temp();
    }
    uint16_t temperature = t1 + t2;
    if (temperature < 5*16 || temperature > 70*16) {
        temperature = 0;
        esp_deep_sleep(1000000LL * 10);
    }

    temp[boot_count] = temperature;

    uint16_t temp_threshold = temp_low;
    for (int i=0; i<4; ++i) {
        if (hours > intervals[i].from && hours < intervals[i].to) {
            temp_threshold = temps[i];
            ESP_LOGI(TAG, "Found mode %d", i);;
            break;
        }
    }
    ESP_LOGI(TAG, "Using temp threshold %d", temp_threshold);
    if (temperature < temp_threshold*16 && status == 0)  {
        status = 1;
        ESP_LOGI(TAG, "Switching ON: %f < %f", temperature/16.0, 1.0*temp_threshold);
        gpio_hold_dis(GPIO_OUT);
        gpio_set_level(GPIO_OUT, 1);
        gpio_hold_en(GPIO_OUT);
        gpio_deep_sleep_hold_en();
    } else if (temperature > (temp_threshold + 1)*16 && status == 1) {
        status = 0;
        ESP_LOGI(TAG, "Switching OFF: %f ~> %f", temperature/16.0, 1.0*temp_threshold);
        gpio_hold_dis(GPIO_OUT);
        gpio_set_level(GPIO_OUT, 0);
        gpio_hold_en(GPIO_OUT);
        gpio_deep_sleep_hold_en();
    }

    temp[boot_count] |= status ? 0x8000: 0;
    boot_count++;
    if (boot_count >= 10) {
        boot_count = 0;
        init_spiffs();
        FILE *f;
        f = fopen("/spiffs/foo.txt", "a");
        if (f == NULL) {
            ESP_LOGE(TAG, "Failed to open file for writing");
            return;
        }
        for (int i=0; i<10; ++i) {
            fputc(temp[i]&0xFF, f);
            fputc((temp[i]>>8)&0xFF, f);
        }
        fclose(f);
        esp_vfs_spiffs_unregister(spiffs_conf.partition_label);
        ESP_LOGI(TAG, "SPIFFS unmounted");
    }
    ESP_LOGI(TAG, "Entering deep sleep for %d seconds", 1);
    gpio_deep_sleep_hold_en();
    esp_deep_sleep(1000000LL * 60);
}
