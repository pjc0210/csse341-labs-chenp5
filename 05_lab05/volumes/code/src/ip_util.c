// SPDX-License-Identifier: Unlicense

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "ip_util.h"
#include "icmp_util.h"

void
parse_ip(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
         unsigned len)
{
  struct iphdr *iphdr;
  uint8_t protocol;
  //struct in_addr addr;

  // move forward to the ip header
  iphdr    = (struct iphdr *)(pkt + sizeof(struct ether_header));
  protocol = iphdr->protocol;

  // TODO:
  // =====
  //  Remove these two lines once you're starting, they're here to silence the
  //  compiler warnings.
  //(void)protocol;
  //(void)addr;

  // TODO:
  // =====
  //  Add code here to call the function parse_icmp in case the IPv4 header
  //  tells you that there is an IMCP header following it.
  //
  //  This should be fairly simply, just adapt your code from the previous lab.
  if (protocol == IPPROTO_ICMP) {
    printf("Parsing ICMP packet...\n");
    parse_icmp(pkt, my_mac_addr, handle, len);
  }
}
