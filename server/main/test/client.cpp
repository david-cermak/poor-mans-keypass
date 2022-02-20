#include "client.h"
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sys/socket.h>
#include "tls.h"
#include "storage/tls_keys.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <termios.h>
#include <sys/ioctl.h>

class Test_Tls : public Tls {
public:
  void set_sock(int s) {
    sock_ = s;
  }
    int send(const unsigned char *buf, size_t len) override
    {
        printf("Trying to write %d\n", len);
        for (int i=0; i<len; ++i)
            printf("0x%0x, ", buf[i]);
        return ::write(sock_, buf, len);
        for (int i=0; i<len; ++i) {

            unsigned char in[2] = { static_cast<unsigned char>('0' +(buf[i]&0xF)), static_cast<unsigned char>('0' + (0xF&(buf[i] >>4))) };

            int out = ::write(sock_, in, 1);
            if (out <= 0) {
                printf("\nWriting %d\n", i);
                return i;
            }
            while (::write(sock_, in+1, 1) <= 0) {}
            usleep(10000);
        }
        printf("\nWriting %d\n", len);

        return len;
//        int l = ::write(sock_, buf, len);
//        if (l == -1)
//            return 0;
//        return l;
    }

    int recv(unsigned char *buf, size_t len) override
    {
      printf("\nTry to read %d\n", len);
      int real_len;
      while ((real_len = ::read(sock_, buf, len)) < 1)
      { usleep(1000); }
      printf("Read %d\n", real_len);
      for (int i=0; i<real_len; ++i)
        printf("0x%0x, ", buf[i]);
      printf("\nRead %d\n", real_len);

      return real_len;
        for (int i=0; i<len; ++i) {
            unsigned char c1;
            unsigned char c2;
            while (::read(sock_, &c1, 1) <= 0) {
                if (i > 0) {
                    printf("\nReading %d\n",i);
                    return i;
                }
                usleep(10000);
            }
            while (::read(sock_, &c2, 1) <= 0) {
                usleep(10000);
            }
            buf[i] = (0xF&(c1-'0')) + ((0x0F&(c2-'0'))<<4);
            printf("0x%0x, ", buf[i]);
        }
        printf("\nReading %d\n",len);
        return len;
//        int l;
//        while ((l = ::read(sock_, buf, len)) <= 0) {
//
//        }
////        printf("Reading %d %.*s\n",l, l, buf);
//        return l;
    }

};
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
//  tls.set_sock(fd);
//  while (true) {
//    for (int i=0; i<256; ++i) {
//      buf[i] = i;
//    }
//      tls.send(buf, 256);
//      int r = tls.recv(buf, 256);
//      printf( "Received %d %x\n", r, buf[0] );
//  }
//    while
//    Tls tls;
    tls.set_own_cert(tls_keys::get_client_cert(), tls_keys::get_client_key());
    tls.init(false, false);
    if (tls.handshake(fd) == -1) {
        printf( "FAILED!" );
        return false;
    }
    printf( "handshake OK!" );
    tls.write(reinterpret_cast<const unsigned char *>("test_string12345"), 15);
    tls.write(reinterpret_cast<const unsigned char *>("test_string12345"), 15);
//    unsigned char buf [100];
    int size = tls.read(buf, sizeof(buf));
    printf("size=%d\n", size);
    printf("%.*s", size, buf);

    return true;
}
