// SPDX-License-Identifier: Unlicense

#ifndef _PRINT_ICMP_H
#define _PRINT_ICMP_H

#include <pcap/pcap.h>

/**
 * Parse an ICMP packet and print out its content.
 *
 * @param pkt     The byte content of packet.
 * @param hdr     The pcap header containing metadata.
 * @param handle  The pcap handle for error checking.
 *
 * @return 0 on success, -1 on failure.
 */
int parse_icmp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle);

#endif // print_icmp.h
