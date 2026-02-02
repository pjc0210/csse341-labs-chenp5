// SPDX-License-Identifier: Unlicense

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
  int len = sizeof(struct ether_header) + sizeof(struct ether_arp);
  pkt = malloc(len);
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

  // handle if dmac is NULL
  if (dmac == NULL) {
    if (type == ARP_PKT_REQUEST) {
      dmac = "00:00:00:00:00:00";
    } else if (type == ARP_PKT_GRATUITOUS) {
      dmac = "ff:ff:ff:ff:ff:ff";
    }
  }

  //  Set the destination MAC address.
  //  Use a switch statement depending on the `type`.
  switch (type) {
    case ARP_PKT_REQUEST:
      eth_addr = ether_aton("ff:ff:ff:ff:ff:ff");
      memcpy(eth->ether_dhost, eth_addr->ether_addr_octet, sizeof eth->ether_dhost);
      break;

    case ARP_PKT_REPLY:
      eth_addr = ether_aton(dmac);
      memcpy(eth->ether_dhost, eth_addr->ether_addr_octet, sizeof eth->ether_dhost);
      break;

    case ARP_PKT_GRATUITOUS:
      eth_addr = ether_aton("ff:ff:ff:ff:ff:ff");
      memcpy(eth->ether_dhost, eth_addr->ether_addr_octet, sizeof eth->ether_dhost);
      break;

    default:
      // error
      print_err("Unsupported type\n");
      perror("[PANIC]: ");
      exit(EXIT_FAILURE);

  }

  //  Set the Ethernet type field
  eth->ether_type = htons(0x0806);

  // TODO:
  //  Set up ARP packet operation type. That depends on the `type` variable.
  switch (type) {
    case ARP_PKT_REQUEST:
      arp->ea_hdr.ar_op = htons(0x0001);
      break;

    case ARP_PKT_REPLY:
      arp->ea_hdr.ar_op = htons(0x0002);
      break;

    case ARP_PKT_GRATUITOUS:
      arp->ea_hdr.ar_op = htons(0x0002);
      break;

    default:
      // print error + exit
      print_err("Unsupported type\n");
      perror("[PANIC]: ");
      exit(EXIT_FAILURE);

  }

  //  Set the ARP hardware protocol and address length
  arp->ea_hdr.ar_hrd = htons(0x0001);
  arp->ea_hdr.ar_hln = 6;

  //  Set the ARP target protocol and length
  arp->ea_hdr.ar_pro = htons(0x0800);
  arp->ea_hdr.ar_pln = 4;

  //  Set up source ARP fields
  //  Those are: arp->arp_sha and arp->arp_spa
  //  I give you to way to set arp->arp_spa below
  inet_aton(sip, &addr);
  memcpy(arp->arp_spa, &addr.s_addr, 4); // ip

  eth_addr = ether_aton(smac); // mac
  memcpy(arp->arp_sha, eth_addr, sizeof arp->arp_sha);
  
  //  Set up destination ARP fields
  //  Those are: arp->arp_tha and arp->arp_tpa
  inet_aton(dip, &addr);
  memcpy(arp->arp_tpa, &addr.s_addr, 4); // ip

  eth_addr = ether_aton(dmac); // mac
  memcpy(arp->arp_tha, eth_addr, sizeof arp->arp_tha);


  // TODO:
  //  Loop depending on `npkts` and send one packet each time.
  //   Do not recreate the packet, just send the same one over and over again.
  //
  //   Make sure to add `sleep(1);` between each packet to be nice to the
  //   docker network.
  while (count < npkts || npkts == -1) {
    pcap_inject(handle, pkt, len);
    sleep(1);
    count++;
  }

  //
  //  Free the packet and leave. Return the total number of packets sent.
  //    Note: if `npkts` is -1, then we will never reach here except on error.

  free(pkt);
  print_log("Done sending packets....\n");
  return count;
}
