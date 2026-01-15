// SPDX-License-Identifier: Unlicense

#ifndef _PRINT_ICMP_H
#define _PRINT_ICMP_H

#include <pcap/pcap.h>

/**
 *  This function parses an icmp header and takes appropriate action based on
 *  that header.
 *
 * @param pkt   The pointer to the START of the packet.
 * @param my_mac_addr   The MAC address of the machine running this code,
 *                      passed as a string.
 * @param handle        The pcap_t handle obtained from main.
 * @param len           The total length of the packet.
 *
 */
void parse_icmp(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
                unsigned len);

#endif // print_icmp.h
