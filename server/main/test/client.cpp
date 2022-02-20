#include "client.h"
#include <unistd.h>
#include <cstdio>
#include <sys/socket.h>
#include "tls.h"
#include "storage/tls_keys.h"
#include <cerrno>
#include <fcntl.h>
#include <cstring>
#include <termios.h>
#include <sys/ioctl.h>

class Test_Tls : public Tls {
public:
  void set_sock(int s) {
    sock_ = s;
  }
    int send(const unsigned char *buf, size_t len) override
    {
        return ::write(sock_, buf, len);
    }

    int recv(unsigned char *buf, size_t len) override
    {
      int real_len;
      while ((real_len = ::read(sock_, buf, len)) < 1)
      { usleep(1000); }
      return real_len;
    }

};

static const unsigned char to_decrypt[] = {126, 200, 113, 150, 184, 40, 214, 157, 225, 210, 53, 192, 187, 211, 45, 76, 171, 163, 155, 187, 122, 22, 8, 240, 95, 54, 210, 180, 13, 134, 61, 4, 51, 97, 221, 94, 12, 244, 97, 227, 34, 224, 236, 116, 24, 69, 88, 5, 41, 58, 242, 187, 235, 81, 97, 66, 243, 180, 177, 45, 251, 85, 101, 255, 220, 148, 56, 24, 170, 54, 191, 144, 233, 62, 161, 135, 57, 151, 72, 54, 83, 225, 211, 36, 190, 221, 16, 142, 160, 35, 19, 248, 3, 113, 226, 149, 255, 148, 154, 146, 173, 51, 97, 149, 94, 196, 5, 83, 79, 115, 196, 169, 184, 90, 13, 187, 120, 109, 218, 1, 244, 249, 222, 191, 148, 190, 6, 177, 30, 61, 0, 118, 226, 19, 251, 79, 127, 171, 120, 89, 245, 82, 82, 155, 91, 47, 247, 157, 100, 27, 26, 88, 18, 86, 165, 183, 244, 0, 245, 54, 190, 46, 3, 216, 106, 35, 172, 224, 110, 180, 96, 209, 132, 14, 0, 243, 109, 132, 157, 129, 86, 254, 94, 9, 142, 141, 1, 75, 1, 38, 171, 152, 45, 107, 183, 139, 202, 105, 35, 226, 23, 93, 251, 115, 100, 67, 33, 131, 106, 68, 163, 207, 68, 71, 149, 170, 68, 204, 93, 177, 141, 99, 215, 179, 156, 96, 70, 85, 78, 155, 115, 240, 254, 196, 56, 24, 78, 49, 246, 128, 5, 200, 99, 154, 43, 3, 93, 157, 192, 15, 252, 108, 238, 165, 25, 79};

bool client::init() {
    int fd;
    fd = open ("/dev/ttyUSB1", O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0)
    {
        printf ("error %d opening %s: %s", errno, "/dev/ttyUSB1", strerror (errno));
        return false;
    }
#ifndef ESP_PLATFORM
  struct termios tty = {};
  tty.c_cflag &= ~PARENB;
  tty.c_cflag &= ~CSTOPB;
  tty.c_cflag &= ~CSIZE; // Clear all the size bits, then use one of the statements below
  tty.c_cflag |= CS8; // 8 bits per byte (most common)
  tty.c_cflag &= ~CRTSCTS; // Disable RTS/CTS hardware flow control (most common)
  tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)
  tty.c_lflag &= ~ICANON;
  tty.c_lflag &= ~ECHO; // Disable echo
  tty.c_lflag &= ~ISIG; // Disable interpretation of INTR, QUIT and SUSP
  tty.c_iflag &= ~(IXON | IXOFF | IXANY); // Turn off s/w flow ctrl
  tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL); // Disable any special handling of received bytes
  tty.c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
  tty.c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed
  tty.c_cc[VTIME] = 0;
  tty.c_cc[VMIN] = 0;
  cfsetispeed(&tty, B115200);
  cfsetospeed(&tty, B115200);
  cfsetspeed(&tty, B115200);
  ioctl(fd, TCSETS, &tty);
  int opts;
  opts = fcntl(fd,F_GETFL);
  opts = opts & (~O_NONBLOCK);
  if (fcntl(fd,F_SETFL,opts) < 0) {
    perror("fcntl(F_SETFL)");
  }
#endif
    unsigned char buf [256];
//    int total = 0;
//    while (1) {
//        int n = read(fd, buf, sizeof buf);  // read up to 100 characters if ready to read
//        printf("%.*s", n, buf);
//        total += n;
//        if (total > 200)
//            break;
//    }

//    struct addrinfo hints = {};
//    struct addrinfo *addr_list, *cur;
//    struct sockaddr_in *serv_addr = nullptr;
//    hints.ai_family = AF_UNSPEC;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_protocol = IPPROTO_TCP;
//    if ( getaddrinfo("192.168.10.105", "3344", &hints, &addr_list ) != 0 ) {
//        return false;
//    }
//    fd = -1;
//    for ( cur = addr_list; cur != nullptr; cur = cur->ai_next ) {
//        fd = socket( cur->ai_family, cur->ai_socktype, cur->ai_protocol );
//        if ( fd < 0 ) {
//            fd = -1;
//            continue;
//        }
//        serv_addr = (struct sockaddr_in *)cur->ai_addr;
//        if ( connect( fd, (struct sockaddr *)serv_addr, cur->ai_addrlen ) != 0 ) {
//            printf("Cannot connect!\n");
//            close( fd );
//            fd = -1;
//            continue;
//        }
//        break;
//    }
//    if (fd == -1) {
//        return false;
//    }
    Test_Tls tls;
    tls.set_own_cert(tls_keys::get_client_cert(), tls_keys::get_client_key());
    tls.init(false, false);
    if (tls.handshake(fd) == -1) {
        printf( "FAILED!" );
        return false;
    }
    printf( "handshake OK!\n" );
    tls.write(to_decrypt, sizeof(to_decrypt));
//    unsigned char buf [100];
    int size = tls.read(buf, sizeof(buf));
    printf("size=%d\n", size);
    printf("%.*s\n", size, buf);
    return true;
}
