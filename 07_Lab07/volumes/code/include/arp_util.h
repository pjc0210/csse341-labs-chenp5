// SPDX-License-Identifier: Unlicense

#ifndef _ARP_UTIL_H
#define _ARP_UTIL_H

#include <pcap.h>

enum ARP_PKT_TYPE {
  ARP_PKT_REQUEST,    //!< An ARP request packet
  ARP_PKT_REPLY,      //!< An ARP reply packet
  ARP_PKT_GRATUITOUS, //!< An ARP Gratuitous packet

  ARP_PKT_LASTONE
};

/**
 * Send npkts ARP packet of type type (from enum above).
 *
 * @param handle  The pcap handle to send on.
 * @param npkts   The number of packets to send (-1, if send forever)
 * @param type    The type of the packets to send (see enum ARP_PKT_TYPE)
 * @param smac    String representation of the source MAC address.
 * @param dmac    String representation of the destination MAC address (can be
 *                  NULL).
 * @param sip     String representation of the source IP address, if any.
 * @param dip     String representation of the destionation IP address, if any.
 *
 * @return the number of packets sent, 0 indicating failure.
 *  Note this function does not return if npkts is -1.
 */
int send_arp_packets(pcap_t *handle, int npkts, int type, const char *smac,
                     const char *dmac, const char *sip, const char *dip);

#endif // arp_util.h
