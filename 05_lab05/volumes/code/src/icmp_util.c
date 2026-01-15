// SPDX-License-Identifier: Unlicense

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "icmp_util.h"
#include "util.h"
#include "log.h"

void
parse_icmp(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
           unsigned len)
{
  struct iphdr *iphdr;
  struct icmphdr *icmphdr;
  struct ether_addr *eth_addr;
  u_char *retpkt;

  iphdr = (struct iphdr *)(pkt + sizeof(struct ether_header));
  icmphdr =
      (struct icmphdr *)(pkt + sizeof(struct ether_header) + sizeof *iphdr);
  eth_addr = ether_aton(my_mac_addr);

  // TODO:
  // =====
  //  Remove these lines once you're starting, they're here to silence the
  //  compiler warnings.
  //(void)icmphdr;
  //(void)eth_addr;
  //(void)retpkt;

  // TODO:
  // =====
  //
  //  1. Check if the ICMP header is an Echo request, if so, just print that
  //     you have received it, and the source from which it originated.
  //     Recall that the source IPv4 address is in the IPv4 header, not the
  //     ICMP header.
  struct ether_header *eth_hdr;
  struct icmphdr *reticmp;

  if (icmphdr->type == 8) {
    printf("Received Echo request from %s\n", ip_to_str(&iphdr->saddr));
  
  //  2. Send an ICMP Echo Reply to whoever sent you the request.
  //     Here's on approach to do:
  //
  //     2.1 Allocate room for the new packet, use retpkt from above.
    retpkt = malloc(len);
    if (!retpkt) {
      print_err("PANIC: No more room in memory\n");
      exit(99);
    }

  //     2.2 Copy the old packet into the new one, using memcpy.
  //          Hint: we know the full size of the packet already, it is len!
    memcpy(retpkt, pkt, len);

  //     2.3 Adjust the fields of each header that need to be adjusted.
    eth_hdr = (struct ether_header *)retpkt;
    iphdr = (struct iphdr *)(retpkt + sizeof(struct ether_header));
    reticmp = (struct icmphdr *)(retpkt + sizeof(struct ether_header) + sizeof(struct iphdr));

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_shost, eth_addr->ether_addr_octet, sizeof eth_hdr->ether_shost);

    uint32_t tmp_addr = iphdr->daddr;
    iphdr->daddr = iphdr->saddr;
    iphdr->saddr = tmp_addr;

    reticmp->type = 0;
    reticmp->code = 0;

    // change checksum
    reticmp->checksum = 0;
    reticmp->checksum = chksum((uint16_t *)reticmp, ntohs(iphdr->tot_len) - sizeof(struct iphdr));
    
    iphdr->check = 0;
    iphdr->check = chksum((uint16_t *)iphdr, sizeof(struct iphdr));

  //     2.4 Use pcap_inject(handle, retpkt, len); to send the packet on the
  //         wire.
    pcap_inject(handle, retpkt, len);

  //     2.5 Free the retpkt to make sure you have no memory LEAKS.
    free(retpkt);
  }
}
