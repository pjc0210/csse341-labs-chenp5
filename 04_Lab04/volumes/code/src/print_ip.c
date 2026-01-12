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

static const char *ip_proto_to_str(struct iphdr *ip) {
  switch(ip->protocol) {
    case IPPROTO_ICMP:
      return "ICMP";
      break;
    case IPPROTO_TCP:
      return "TCP";
      break;
    case IPPROTO_UDP:
      return "UDP";
      break;
    default:
      return "UNKNOWN";
  }
}

int
parse_ip(const u_char *pkt, struct pcap_pkthdr *hdr, pcap_t *handle)
{
  // TODO:
  // ======
  //  Add code here to print the content of an IP packet.
  //static char logfmt[1024];
  //char *str = logfmt;
  struct ether_header *eth_hdr;
  eth_hdr = (struct ether_header *)pkt;

  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
    struct iphdr *ip;
    ip = (struct iphdr *)(pkt + sizeof *eth_hdr);
    print_log("(%s) Received an IPv4 packet:\n", fmt_ts(&hdr->ts));

    printf("+---------------------------------------------------------+\n");
    printf(" %-20s %-20s \n",   "Field",          "Value");
    printf(" %-20s %-20x \n",   "Version",        ip->version);
    printf(" %-20s 0x%-20x \n", "ID",             ntohs(ip->id));
    printf(" %-20s %-20u \n",   "TTL",            ip->ttl);
    printf(" %-20s %-20u \n",   "Protocol",       ip->protocol);
    printf(" %-20s %-20s \n",   "Parsed Prot",    ip_proto_to_str(ip));
    printf(" %-20s %-20s \n",   "Source IP",      ip_to_str(&ip->saddr));
    printf(" %-20s %-20s \n",   "Destination IP", ip_to_str(&ip->daddr));
    printf("+---------------------------------------------------------+\n");

    if (ip->protocol == IPPROTO_ICMP) {
      parse_icmp(pkt, hdr, handle);
    }
  }

  return 0;
}


