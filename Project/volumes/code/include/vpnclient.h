// SPDX-License-Identifier: Unlicense

#ifndef _VPNCLIENT_H
#define _VPNCLIENT_H

#include <netinet/in.h>

/**
 * Callback function when receiving a packet over the TUN interface.
 *
 * @param tunfd   The file descriptor for the TUN device.
 * @param sockfd  The socket file descriptor for the UDP peer server
 * @param server  The server's UDP peer address (IP, PORT)
 *
 */
void tun_callback(int tunfd, int sockfd, struct sockaddr_in *server);

/**
 * Callback function when receiving a packet over the UDP socket.
 *
 * @param tunfd   The tunnel file descriptor.
 * @param sockfd  The socket file descriptor for the UDP peer server.
 * @param server  The server's UDP peer address (IP, PORT)
 */
void sock_callback(int tunfd, int sockfd, struct sockaddr_in *server);

/**
 * Check the checksum of a WireChild packet.
 *
 * @param wc           The WireChild packet.
 * @param payload_len  The length of the payload.
 *
 * @return 1 if the checksum is valid, 0 otherwise.
 */
int
check_checksum(struct WireChild *wc, size_t payload_len);

/**
 * Perform a handshake with the peer server
 *
 * @param sockfd    The UDP socket file descriptor
 * @param server    The server's UDP peer address (IP, PORT)
 *
 * @return 0 on success, -1 on error.
 */
int perform_handshake(int sockfd, struct sockaddr_in *server);

#endif // vpnclient.h
