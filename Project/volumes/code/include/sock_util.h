// SPDX-License-Identifier: Unlicense

#ifndef _SOCK_UTIL_H
#define _SOCK_UTIL_H

#include <stdint.h>

struct sockaddr_in;

struct WireChild {
    char W;
    char C;
    unsigned char version;
    unsigned char type; // in hex
    unsigned short length;
    unsigned short checksum;
    unsigned int seq_num;
    unsigned int session_id;
    unsigned int unused; // reserved for future use
};

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

/**
 * Client side: connect through a UDP socket to the server.
 *
 * @param ip    The IPv4 address of the server to connect to.
 * @param port  The port number to connect to.
 * @param addr  The sockaddr structure for the server.
 *
 * @return the socket file descriptor on success, -1 on failure.
 */
int connect_udp_sock(const char *ip, uint16_t port, struct sockaddr_in *addr);

/**
 * Server side: bind to a UDP socket on a given ip and port.
 *
 * @param ip    The IPv4 address to bind to.
 * @param port  The port number to bind to.
 *
 * @return the socket's file descriptor on success, -1 on failure.
 */
int bind_udp_sock(const char *ip, uint16_t port);

#endif // sock_util.h
