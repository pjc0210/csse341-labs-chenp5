// SPDX-License-Identifier: Unlicense
//
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>

#include "log.h"
#include "print_icmp.h"
#include "util.h"

static const char *icmp_type_to_str(struct icmphdr *icmp) {
  switch (icmp->type) {
    case 0:
      return "Echo (Ping) Reply";
      break;
    case 3:
      return "Destination Unreachable";
      break;
    case 5:
      return "Redirect";
      break;
    case 8:
      return "Echo (Ping) Request";
      break;
    case 11:
      return "Time Exceeded";
      break;
    case 12:
      return "Parameter Problem";
      break;
    default:
      return "UNKNOWN";
  }
}

int
parse_icmp(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  // TODO:
  // ======
  //  Add code here to print the content of an ICMPP packet.
  struct ether_header *eth_hdr; 
  struct iphdr *ip_hdr;
  struct icmphdr *icmp;
  
  eth_hdr = (struct ether_header *)pkt;
  ip_hdr = (struct iphdr *)(pkt + sizeof *eth_hdr);
  icmp = (struct icmphdr *)(pkt + sizeof *eth_hdr + sizeof *ip_hdr);
  
  print_log("(%s) Received an ICMP packet:\n", fmt_ts(&hdr->ts));

  printf("+---------------------------------------------------------+\n");
  printf(" %-20s %-20s \n",   "Field",    "Value");
  printf(" %-20s %-20s \n",   "Type",     icmp_type_to_str(icmp));
  printf(" %-20s %-20u \n",   "Code",     icmp->code);
  printf(" %-20s %-20x \n",   "Checksum", icmp->checksum);
  printf("+---------------------------------------------------------+\n");

  return 0;
}
