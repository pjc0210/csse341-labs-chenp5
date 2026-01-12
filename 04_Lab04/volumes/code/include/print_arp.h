// SPDX-License-Identifier: Unlicense

#ifndef _PRINT_ARP_H
#define _PRINT_ARP_H

#include <pcap/pcap.h>

/**
 * Parse an ARP packet and print out its content.
 *
 * @param pkt     The byte content of packet.
 * @param hdr     The pcap header containing metadata.
 * @param handle  The pcap handle for error checking.
 *
 * @return 0 on success, -1 on failure.
 */
int parse_arp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle);

#endif // print_arp.h
