// SPDX-License-Identifier: Unlicense

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

#include "log.h"
#include "print_arp.h"
#include "util.h"

int
parse_arp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  static char logfmt[1024];
  char *str = logfmt;
  struct ether_header *eth;
  struct ether_arp *arp;
  u_short a_op;
  const char *ip, *mac;

  // Grab the Ethernet header from the packet, simply cast the bytes to be
  // interpreted as an Ethernet header.
  eth  = (struct ether_header *)pkt;
  arp  = (struct ether_arp *)(pkt + sizeof *eth);
  // Watch out here that we must translate from network order to host order.
  a_op = ntohs(arp->ea_hdr.ar_op);

  if(a_op == ARPOP_REQUEST) {
    // The ARP request has the following meaningful fields:
    //  - spa: Source physical address.
    //  - sha: Source hardware address.
    //  - tpa: Target physical address.
    //  - tha: Target hardware address.
    ip = ip_to_str((void *)arp->arp_tpa);
    str += sprintf(str, "Who has %s? ", ip);

    ip = ip_to_str((void *)arp->arp_spa);
    str += sprintf(str, "tell %s!\n", ip);

    mac = mac_to_str((void *)arp->arp_sha);
    str += sprintf(str, "\t\tFrom %s ", mac);

    mac = mac_to_str((void *)arp->arp_tha);
    str += sprintf(str, "to %s.", mac);

    print_log("(%s) %s\n", fmt_ts(&hdr->ts), logfmt);
  } else if(a_op == ARPOP_REPLY) {
    // ARP Reply, simpy print out where the target is.
    ip  = ip_to_str((void *)arp->arp_spa);
    mac = mac_to_str((void *)arp->arp_sha);

    print_log("(%s) %s is at %s\n", fmt_ts(&hdr->ts), ip, mac);
  }

  return 0;
}
