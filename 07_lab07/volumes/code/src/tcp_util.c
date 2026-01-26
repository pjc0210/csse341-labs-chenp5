// SPDX-License-Identifier: Unlicense

#include <arpa/inet.h>
#include <linux/tcp.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tcp_util.h"
#include "util.h"

// TODO:
// =====
//  Change these values to the source MAC address of hostA and hostB.
#define HOST_A_MAC "ce:76:c2:0f:73:5d"
#define HOST_B_MAC "7a:6e:11:5a:0a:ae"

void
parse_tcp(const u_char *pkt, const char *my_mac_addr, pcap_t *handle,
          unsigned len)
{
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct ether_header *eth;
  struct ether_addr *eth_addr;
  static struct in_addr host_a_addr;
  static struct in_addr host_b_addr;

  eth = (struct ether_header *)pkt;
  ip  = (struct iphdr *)(pkt + sizeof *eth);
  tcp = (struct tcphdr *)(pkt + sizeof *eth + sizeof *ip);

  inet_aton("10.10.0.4", &host_a_addr);
  inet_aton("10.10.0.5", &host_b_addr);

  // TODO:
  //  Remove these lines, they're only here to silence the compiler.
  //(void)tcp;
  //(void)eth_addr;

  // TODO:
  //=====
  //   Complete this function to parse a TCP packet and then modify its content
  //   to replace everything with a letter of your choice (or choose something
  //   more fun)! 

  // 1. You will need to fix the Ethernet header's source and destination MAC
  //    addresses, depending on where it's coming from.
  //
  //    _Hint_: Recall that you are posing as both hostA and hostB.
  //
  if(ip->saddr == host_a_addr.s_addr) {
    // packet coming from host a to host b, how should it reach b?
    eth_addr = ether_aton(my_mac_addr);
    memcpy(eth->ether_shost, eth_addr->ether_addr_octet, sizeof eth->ether_shost);
    eth_addr = ether_aton(HOST_B_MAC);
    memcpy(eth->ether_dhost, eth_addr->ether_addr_octet, sizeof eth->ether_dhost);

  } else if(ip->saddr == host_b_addr.s_addr) {
    // packet coming from host b to host a, how should it reach a?
    eth_addr = ether_aton(my_mac_addr);
    memcpy(eth->ether_shost, eth_addr->ether_addr_octet, sizeof eth->ether_shost);
    eth_addr = ether_aton(HOST_A_MAC);
    memcpy(eth->ether_dhost, eth_addr->ether_addr_octet, sizeof eth->ether_dhost);
  }

  // 2. Check if the packet contains data and then modify the data in the
  //    packet.
  if (tcp->ack && tcp->psh) {
    uint16_t tot_len = ntohs(ip->tot_len);
    uint16_t iphdr_len = sizeof(struct iphdr);
    uint16_t tcp_hdr_len = tcp->doff * 4;
    uint16_t data_len = tot_len - iphdr_len - tcp_hdr_len;

    char *data = (char *) tcp + tcp_hdr_len;
    for (int i = 0; i < data_len; i++, data++) {
      if (*data == '\0' || *data == '\n') {
        break;
      } else if (i == 0) {
        *data = 'h';
      } else {
        *data = 'i';
      }
    }
  }

  // 3. Compute checksum for both the TCP header and the IP header.
  tcp->check = 0;
  tcp->check = compute_tcp_checksum(tcp, ip);

  // 4. Send the packet, this is the same code from previous labs.
  int rc = pcap_inject(handle, pkt, len);
  if(rc == PCAP_ERROR_NOT_ACTIVATED) {
    print_err("Pcap was not actived!\n");
    exit(EXIT_FAILURE);
  } else if(rc == PCAP_ERROR) {
    print_err("Pcap error: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
}

uint16_t
compute_tcp_checksum(struct tcphdr *tcp, struct iphdr *ip)
{
  unsigned long cksum = 0;
  uint16_t tcplen     = ntohs(ip->tot_len) - (ip->ihl * 4);
  struct pseudo_tcp_hdr pseudohdr;
  uint16_t *hdr;
  uint32_t len;

  // make sure this is zero.
  tcp->check = 0;

  // fill up the pseudo header
  pseudohdr.saddr   = ip->saddr;
  pseudohdr.daddr   = ip->daddr;
  pseudohdr.zero    = 0;
  pseudohdr.ptcl    = ip->protocol;
  pseudohdr.tcp_len = htons(tcplen);

  // start over the pseudoheader
  len = sizeof pseudohdr;
  hdr = (uint16_t *)(&pseudohdr);
  while(len > 1) {
    cksum += *hdr++;
    len -= sizeof(uint16_t);
  }

  // pseudo header is always 96 bits or 24 bytes, which means len is 0 now.
  len = tcplen;
  hdr = (uint16_t *)tcp;
  while(len > 1) {
    cksum += *hdr++;
    len -= sizeof(uint16_t);
  }

  if(len)
    cksum += *(u_char *)hdr;

  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >> 16);

  return (uint16_t)~cksum;
}
