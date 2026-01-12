// SPDX-License-Identifier: Unlicense
//

#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "log.h"
#include "print_icmp.h"
#include "print_ip.h"
#include "util.h"

int
parse_ip(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  // TODO:
  // ======
  //  Add code here to print the content of an IP packet.

  return 0;
}
