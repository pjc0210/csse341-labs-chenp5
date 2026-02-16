// SPDX-License-Identifier: Unlicense

#ifndef _VPNSERVER_H
#define _VPNSERVER_H

#include <netinet/in.h>

/**
 * Callback function when receiving a packet over the TUN interface.
 *
 * @param tunfd   The file descriptor for the TUN device.
 * @param sockfd  The socket file descriptor for the UDP peer server
 * @param client  The client's UDP peer address (IP, PORT)
 *
 */
void srv_tun_callback(int tunfd, int sockfd, struct sockaddr_in *client);

/**
 * Callback function when receiving a packet over the UDP socket.
 *
 * @param tunfd   The tunnel file descriptor.
 * @param sockfd  The socket file descriptor for the UDP peer server.
 * @param client  The client's UDP peer address (IP, PORT)
 */
void srv_sock_callback(int tunfd, int sockfd, struct sockaddr_in *client);

/**
 * Check the checksum of a WireChild packet.
 *
 * @param pkt          The packet.
 * @param payload_len  The length of the payload.
 *
 * @return 1 if the checksum is valid, 0 otherwise.
 */
int
check_checksum(void *pkt, size_t payload_len);

/**
 * Listen for an incoming handshake from a client.
 *
 * @warning
 *   The assumption is that only one client connects at a time, so don't try to
 *   do this from more than one until you add support for that.
 *
 * @param sockfd    The UDP socket file descriptor
 * @param server    The server's UDP peer address (IP, PORT)
 *
 * @return 0 on success, -1 on error.
 */
int lsn_handshake(int sockfd, struct sockaddr_in *client);

#endif // vpnserver.h
