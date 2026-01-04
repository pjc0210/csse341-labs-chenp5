// SPDX-License-Identifier: Unlicense

#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "pcap_util.h"
#include "print_arp.h"
#include "util.h"

// Set the filter to capture only ARP or ICMP packets
static const char *filter_expr = "arp or icmp";

int
main(int argc, char **argv)
{
  pcap_t *handle;
  struct in_addr addr;
  struct pcap_pkthdr *hdr;
  const u_char *pkt;
  struct ether_header *eth_hdr;
  uint16_t eth_type_field; // the ether type field
  int rc;

  // Find the handle for listening to on the interface.
  handle = find_pcap_dev("eth0", &addr, filter_expr);

  // This is the main loop to listen for packets.
  while((rc = pcap_next_ex(handle, &hdr, &pkt)) >= 0) {
    // We have a packet here so we can parse it.
    eth_hdr        = (struct ether_header *)pkt;
    eth_type_field = ntohs(eth_hdr->ether_type);

    // Check if it's an ARP packet
    if(eth_type_field == ETHERTYPE_ARP) {
      parse_arp(pkt, hdr, handle);
    } else {
      print_log("(%s) Got a packet of len %d that is not an APR packet!\n",
                fmt_ts(&hdr->ts), hdr->len);
    }
  }

  if(rc == -1) {
    print_err("Error capturing packets: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  return 0;
}
