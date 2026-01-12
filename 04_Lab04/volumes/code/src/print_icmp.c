// SPDX-License-Identifier: Unlicense
//
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

#include "log.h"
#include "print_icmp.h"
#include "util.h"

int
parse_icmp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  // TODO:
  // ======
  //  Add code here to print the content of an ICMPP packet.
  //
  return 0;
}
