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
 * @return 0 on success, -1 on failure.
 */
int parse_ip(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle);

#endif // print_ip.h
