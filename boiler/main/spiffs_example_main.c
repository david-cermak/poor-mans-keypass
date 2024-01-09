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

RTC_DATA_ATTR static int temp = 0;

static const char *TAG = "example";
static EventGroupHandle_t s_wifi_event_group;
static void event_handler(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG,"connect to the AP fail");
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


void try_to_connect()
{
    uint32_t data;
    char host_ip[] = "192.168.0.28";

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
            unlink("/spiffs/foo.txt");
            FILE* f = fopen("/spiffs/foo.txt", "a");
            fputc(0x11, f);
            fputc(0x22, f);
            fclose(f);

        } else if (data == 0x2222) {
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
            while (c1 > 0 && c2 > 0) {
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
        } else {
            struct tm referenceTime = {0};
            referenceTime.tm_year = 2024 - 1900;
            referenceTime.tm_mon = 0;   // January
            referenceTime.tm_mday = 1;  // 1st day
            referenceTime.tm_hour = 0;  // 00 hours
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


void try_wifi()
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
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,1,pdTRUE,pdTRUE, pdMS_TO_TICKS(10000));
    if (bits & 1) {
        ESP_LOGI(TAG, "connected!");
        try_to_connect();
        esp_wifi_disconnect();
    }

}

#define GPIO_OUT 33
RTC_DATA_ATTR static int boot_count = 0;

void app_main(void)
{

    gpio_config_t io_conf = {
            .intr_type = GPIO_INTR_DISABLE,
            .mode = GPIO_MODE_OUTPUT,
            .pin_bit_mask = BIT64(GPIO_OUT),
    };
    gpio_config(&io_conf);

    for(;;) {
//    for (int i=0; i<5; ++i) {
        ESP_LOGI(TAG, "Set to 1!");
        gpio_set_level(GPIO_OUT, 1);
        vTaskDelay(pdMS_TO_TICKS(10000));
        ESP_LOGI(TAG, "Set to 0!");
        gpio_set_level(GPIO_OUT, 0);
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
    gpio_deep_sleep_hold_en();
//    boot_count = 1;
    gpio_hold_dis(GPIO_OUT);
    gpio_set_level(GPIO_OUT, boot_count%2);
    gpio_hold_en(GPIO_OUT);
    ESP_LOGI(TAG, "Set to %d!", boot_count%2);
//    vTaskDelay(pdMS_TO_TICKS(10000));
    gpio_deep_sleep_hold_en();
    ESP_LOGI(TAG, "Boot count: %d", boot_count);
    const int deep_sleep_sec = 60;
    ESP_LOGI(TAG, "Entering deep sleep for %d seconds", deep_sleep_sec);
    gpio_deep_sleep_hold_en();
    esp_deep_sleep(1000000LL * deep_sleep_sec);


    ESP_LOGI(TAG, "Initializing SPIFFS");

    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = NULL,
      .max_files = 5,
      .format_if_mount_failed = true
    };


    // Use settings defined above to initialize and mount SPIFFS filesystem.
    // Note: esp_vfs_spiffs_register is an all-in-one convenience function.
    esp_err_t ret = esp_vfs_spiffs_register(&conf);

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

#ifdef CONFIG_EXAMPLE_SPIFFS_CHECK_ON_START
//    ESP_LOGI(TAG, "Performing SPIFFS_check().");
//    ret = esp_spiffs_check(conf.partition_label);
//    if (ret != ESP_OK) {
//        ESP_LOGE(TAG, "SPIFFS_check() failed (%s)", esp_err_to_name(ret));
//        return;
//    } else {
//        ESP_LOGI(TAG, "SPIFFS_check() successful");
//    }
#endif

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(conf.partition_label, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s). Formatting...", esp_err_to_name(ret));
        esp_spiffs_format(conf.partition_label);
        return;
    } else {
        ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
    }

    // Check consistency of reported partiton size info.
    if (used > total) {
        ESP_LOGW(TAG, "Number of used bytes cannot be larger than total. Performing SPIFFS_check().");
        ret = esp_spiffs_check(conf.partition_label);
        // Could be also used to mend broken files, to clean unreferenced pages, etc.
        // More info at https://github.com/pellepl/spiffs/wiki/FAQ#powerlosses-contd-when-should-i-run-spiffs_check
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "SPIFFS_check() failed (%s)", esp_err_to_name(ret));
            return;
        } else {
            ESP_LOGI(TAG, "SPIFFS_check() successful");
        }
    }

    FILE *f;
#if 0
    ESP_LOGI(TAG, "Opening file");
    f = fopen("/spiffs/foo.txt", "a");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file for writing");
        return;
    }
//    fprintf(f,"AHOJ\n");
//    fflush(f);
    fputc(0x55, f);
    fputc(0xAA, f);
    fclose(f);
    ESP_LOGI(TAG, "File written");
    ESP_LOGI(TAG, "Reading file");
    f = fopen("/spiffs/foo.txt", "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file for reading");
        return;
    }
    int c;
    while ((c=fgetc(f))  > 0) {
        printf("%x\n", c);
    }
    printf("\n");
    fclose(f);
    ESP_LOGI(TAG, "Entering deep sleep for %d seconds", 10);
    esp_deep_sleep(1000000LL * 10);
#endif


    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    // Is time set? If not, tm_year will be (1970 - 1900).

//    if (timeinfo.tm_year < (2016 - 1900)) {
//        ESP_LOGI(TAG, "Time is not set yet. Connecting to WiFi and getting time over NTP.");
//        try_wifi();
//        ESP_LOGI(TAG, "Entering deep sleep for %d seconds", 10);
//        esp_deep_sleep(1000000LL * 10);
//    }


    // Use POSIX and C standard library functions to work with files.
    // First create a file.
//    uint16_t temp = 0x1234;
//    ESP_LOGI(TAG, "Opening file");
    ESP_LOGI(TAG, "temp = %X", temp);
    if (temp != 0) {
        ESP_LOGE(TAG, "temp = %X", temp);

        f = fopen("/spiffs/foo.txt", "a");
        if (f == NULL) {
            ESP_LOGE(TAG, "Failed to open file for writing");
            return;
        }
        int c1 = 0xFF & temp;
        int c2 = 0xFF & (temp >> 8);

        fputc(1+c1, f);
        fputc(1+c2, f);
        ESP_LOGE(TAG, "c1 = %X", c1);
        ESP_LOGE(TAG, "c2 = %X", c2);
//
//        fputc(0xFF & temp, f);
//        fputc(0xFF & (temp >> 8), f);
        fclose(f);
    } else {
        unlink("/spiffs/foo.txt");
        FILE* f = fopen("/spiffs/foo.txt", "a");
        fputc(0x11, f);
        fputc(0, f);
        fclose(f);

    }

    f = fopen("/spiffs/foo.txt", "r");
    int c;
    while ((c=fgetc(f))  >= 0) {
        printf("%x\n", c);
    }
    printf("\n");
    fclose(f);

//    fprintf(f,"%c%c\n\n", temp, temp>>8);
#if 0
    fputc(1+(0xFF & temp), f);
    fputc(1+(0xFF & (temp >> 8)), f);
    fflush(f);
    fclose(f);
    f = fopen("/spiffs/foo.txt", "r");
    int c;
    while ((c=fgetc(f))  > 0) {
        printf("%x\n", c);
    }
    printf("\n");
    fclose(f);
#endif

    uint8_t data[2];
    ESP_ERROR_CHECK(i2c_master_init());
    ESP_LOGI(TAG, "I2C initialized successfully");
    i2c_master_read_from_device(I2C_MASTER_NUM, 0x4f, data, 2, I2C_MASTER_TIMEOUT_MS / portTICK_PERIOD_MS);
    temp = data[1] + 256 * data[0];
    ESP_LOGI(TAG, "temp = %X", temp);
    temp = temp >> 5;
    ESP_LOGI(TAG, "temp = %f", temp/8.0);

//    ESP_LOGI(TAG, "Opening file");
//    f = fopen("/spiffs/foo.txt", "a");
//    if (f == NULL) {
//        ESP_LOGE(TAG, "Failed to open file for writing");
//        return;
//    }
//    fprintf(f,"%c%c\n\n", temp, temp>>8);
//    fputc(0xFF & temp, f);
//    fputc(0xFF & (temp >> 8), f);
//    fflush(f);
//    fclose(f);
//    f = fopen("/spiffs/foo.txt", "r");
//    fclose(f);
    esp_vfs_spiffs_unregister(conf.partition_label);
    ESP_LOGI(TAG, "SPIFFS unmounted");

    ESP_LOGI(TAG, "File written");
    ESP_LOGI(TAG, "Entering deep sleep for %d seconds", 10);
    gpio_deep_sleep_hold_en();
    esp_deep_sleep(1000000LL * 1);

//    // Check if destination file exists before renaming
//    struct stat st;
//    if (stat("/spiffs/foo.txt", &st) == 0) {
//        // Delete it if it exists
//        unlink("/spiffs/foo.txt");
//    }
//
//    // Rename original file
//    ESP_LOGI(TAG, "Renaming file");
//    if (rename("/spiffs/hello.txt", "/spiffs/foo.txt") != 0) {
//        ESP_LOGE(TAG, "Rename failed");
//        return;
//    }

//    // Open renamed file for reading
//    ESP_LOGI(TAG, "Reading file");
//    f = fopen("/spiffs/foo.txt", "r");
//    if (f == NULL) {
//        ESP_LOGE(TAG, "Failed to open file for reading");
//        return;
//    }
//    while ((c=fgetc(f))  > 0) {
//        printf("%c", c);
//    }
//    printf("\n");
//    while (!feof(f)) {
//        fgets(line, sizeof(line), f);
//        ESP_LOGI(TAG, "Read from file: '%s'", line);
//    }
//    fgets(line, sizeof(line), f);
    fclose(f);
    // strip newline
//    char* pos = strchr(line, '\n');
//    if (pos) {
//        *pos = '\0';
//    }
//    ESP_LOGI(TAG, "Read from file: '%s'", line);

    // All done, unmount partition and disable SPIFFS
    esp_vfs_spiffs_unregister(conf.partition_label);
    ESP_LOGI(TAG, "SPIFFS unmounted");
}