// SPDX-License-Identifier: Unlicense

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <string.h>

#include "arp_util.h"
#include "log.h"

int
send_arp_packets(pcap_t *handle, int npkts, int type, const char *smac,
                 const char *dmac, const char *sip, const char *dip)
{
  // TODO:
  // ====
  //  Add code here to craft and send num_req ARP requests.
  //
  //  You should build two headers, an Ethernet header and an ARP header and
  //  set their approriate fields.
  //
  struct ether_header *eth;    // the Ethernet header to fill in.
  struct ether_arp *arp;       // the ARP header to fill in.
  struct ether_addr *eth_addr; // use this to hold Ethernet addresses
  struct in_addr addr;         // use this for ipv4 addresses
  u_char *pkt;                 // the packet to create.
  int count = 0;               // the number of packets sent so far.

  // Allocate enough room for the packet itself to be held in memory.
  pkt = malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
  if(!pkt) {
    print_err(
        "[PANIC]: Could not find room in memory to allocate a new packet!\n");
    perror("[PANIC]: ");
    exit(EXIT_FAILURE);
  }

  // Grab the two headers at the start of the packet and the payload of Eth.
  eth = (struct ether_header *)pkt;
  arp = (struct ether_arp *)(pkt + sizeof *eth);

  // Set the source MAC address
  eth_addr = ether_aton(smac);
  memcpy(eth->ether_shost, eth_addr->ether_addr_octet, sizeof eth->ether_shost);

  // TODO:
  //  Set the destination MAC address.
  //  Use a switch statement depending on the `type`.

  // TODO:
  //  Set the Ethernet type field

  // TODO:
  //  Set up ARP packet operation type. That depends on the `type` variable.

  // TODO:
  //  Set the ARP hardware protocol and address length

  // TODO:
  //  Set the ARP target protocol and length

  // TODO:
  //  Set up source ARP fields
  //  Those are: arp->arp_sha and arp->arp_spa
  //  I give you to way to set arp->arp_spa below
  inet_aton(sip, &addr);
  memcpy(arp->arp_spa, &addr.s_addr, 4);

  // TODO:
  //  Set up destionation ARP fields
  //  Those are: arp->arp_tha and arp->arp_tpa

  // TODO:
  //  Loop depending on `npkts` and send one packet each time.
  //   Do not recreate the packet, just send the same one over and over again.
  //
  //   Make sure to add `sleep(1);` between each packet to be nice to the
  //   docker network.

  //
  //  Free the packet and leave. Return the total number of packets sent.
  //    Note: if `npkts` is -1, then we will never reach here except on error.

  free(pkt);
  print_log("Done sending packets....\n");
  return count;
}
