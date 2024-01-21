#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include <string.h>
#define PORT 3333


int main(int c, char** var) {
    char addr_str[128];

    struct sockaddr_in dest_addr = {};
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listen_sock < 0) {
        printf("Unable to create socket: errno %d", errno);
        return -1;
    }
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    int err = bind(listen_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err != 0) {
        printf("Socket unable to bind: errno %d", errno);
        return -1;
    }

    err = listen(listen_sock, 1);
    if (err != 0) {
        printf("Error occurred during listen: errno %d", errno);
        return -1;
    }
    struct sockaddr_storage source_addr;
    socklen_t addr_len = sizeof(source_addr);
    int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
    if (sock < 0) {
        printf("Unable to accept connection: errno %d", errno);
        return -1;
    }
    printf("Socket accepted ip address: %s\n", inet_ntoa(((struct sockaddr_in *)&source_addr)->sin_addr));


    // Set the target date (January 1, 2024, 00:00:00 UTC)
    struct tm targetTime = {0};
    targetTime.tm_year = 2024 - 1900;
    targetTime.tm_mon = 0;   // January
    targetTime.tm_mday = 1;  // 1st day
    targetTime.tm_hour = 0;  // 00 hours
    targetTime.tm_min = 0;   // 00 minutes
    targetTime.tm_sec = 0;   // 00 seconds

    // Get the current time
    time_t currentTime;
    time(&currentTime);


    // Calculate the difference in seconds
    time_t secondsSince2024 = difftime(currentTime, mktime(&targetTime));

//    secondsSince2024 -= 22*60;
    // Print the result
    printf("Number of seconds since January 1, 2024: %d\n", (int)secondsSince2024);
    uint32_t data = secondsSince2024;
    if (c>1) {
        printf("argv[]=%s\n", var[1]);
        if (strcmp(var[1],"del") == 0) {
            data = 0x1111;
        } else if (strcmp(var[1],"read") == 0) {
            data = 0x2222;
        } else if (strcmp(var[1],"test") == 0) {
            data = 0x1112;
        } else if (strcmp(var[1],"od_get") == 0) {
            char *endptr;
            data = strtoul(var[2], &endptr, 16);
        } else if (strcmp(var[1],"od_set") == 0) {
            char *endptr;
            uint32_t index = strtoul(var[2], &endptr, 16);
            data = strtoul(var[3], &endptr, 10);
            int len = send(sock, &index, 4, 0);
            if (len <= 0) {
                printf("we're done\n");
                return 1;
            }
            len = send(sock, &data, 4, 0);
            if (len <= 0) {
                printf("we're done\n");
                return 1;
            }
        }
    }

    int len = send(sock, &data, 4, 0);

    if (strcmp(var[1],"od_get") == 0) {
        uint32_t temp = 0;
        len = recv(sock, &temp, 4, 0);
        if (len <= 0) {
            printf("we're done\n");
            return 1;
        }
        printf("%d\n", (int)temp);
    }

    if (data == 0x2222) {
        uint16_t temp = 0;
        while (temp != 0xFFFF) {
            int len = recv(sock, &temp, 2, 0);
            if (len <= 0) {
                printf("we're done\n");
                return 1;
            }
            if (temp != 0xFFFF) {
                printf("%0f\n", temp/8.0);

            }
//            printf(">%04x\n", temp);
        }
    }
    // close(sock);

    return 0;
}
