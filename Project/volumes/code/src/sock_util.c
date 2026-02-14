// SPDX-License-Identifier: Unlicense

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "sock_util.h"

struct WireChild {
    char W;
    char C;
    char version;
    char type; // in hex
    short length;
    short checksum;
    int seq_num;
    int session_id;
    int unused; // reserved for future use
}

enum WireType {
    HELLO = 0x01,
    CHALLENGE = 0x02,
    RESPONSE = 0x03,
    ACK = 0x04,
    // unused 0x05 - 0xd9
    DATA = 0xda,
    // unused 0xdb - 0xfe
    ERROR = 0xff
};

int
connect_udp_sock(const char *ip, uint16_t port, struct sockaddr_in *addr)
{
  int fd;

  // open up a socket
  if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    print_err("Failed to create UDP socket: %s\n", strerror(errno));
    return -1;
  }

  memset(addr, 0, sizeof *addr);
  addr->sin_family      = AF_INET; // IPv4
  addr->sin_port        = htons(port);
  addr->sin_addr.s_addr = inet_addr(ip);

  // connect to the server side.
  if(connect(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
    print_err("Could not connect to server (%s, %d): %s\n", ip, port,
              strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

int
bind_udp_sock(const char *ip, uint16_t port)
{
  int fd = -1;
  struct sockaddr_in addr;

  // opne up the UDP socket
  if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    print_err("Failed to create UDP socket: %s\n", strerror(errno));
    return -1;
  }

  // bind to own IP and port number
  memset(&addr, 0, sizeof addr);
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);

  if(bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
    print_err("Could not bind to IPv4 (%s, %d): %s\n", ip, port,
              strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}
