// SPDX-License-Identifier: Unlicense

#ifndef _TCP_UTIL_H
#define _TCP_UTIL_H

#include <pcap.h>

// forward declarations.
struct tcphdr;
struct iphdr;

struct pseudo_tcp_hdr {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t zero;
  uint8_t ptcl;
  uint16_t tcp_len;
};

/**
 * Compute the 16 bits check for a TCP packet.
 *
 * @param tcp   The TCP header.
 * @param ip    The IP header.
 *
 * @return the 16 bits checksum computed according to the TCP specs.
 */
uint16_t compute_tcp_checksum(struct tcphdr *tcp, struct iphdr *ip);

/**
 * Parse a TCP packet and do some nefarious stuff.
 *
 * @param pkt           The byte content of the packet.
 * @param my_mac_addr   The MAC address of the machine running this code.
 * @param handle        The pcap handle for error checking and sending stuff.
 * @param len           The total length of the packet.
 *
 */
void parse_tcp(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
               unsigned len);

#endif // tcp_util.h
