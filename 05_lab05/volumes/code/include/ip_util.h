// SPDX-License-Identifier: Unlicense

#ifndef _PRINT_IP_H
#define _PRINT_IP_H

#include <pcap/pcap.h>

/**
 * Parse an IP packet and print out its content.
 *
 * @param pkt     The byte content of packet.
 * @param hdr     The pcap header containing metadata.
 * @param handle  The pcap handle for error checking.
 *
 */
void parse_ip(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
              unsigned len);

#endif // print_ip.h
