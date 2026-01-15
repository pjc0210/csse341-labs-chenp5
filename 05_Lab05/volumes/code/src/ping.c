#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "ip_util.h"
#include "log.h"
#include "pcap_util.h"

int
main(int argc, char **argv)
{
  pcap_t *handle;
  struct in_addr addr;
  struct pcap_pkthdr *hdr;
  const u_char *pkt;
  struct ether_header *eth_hdr;
  int rc;
  const char *my_mac_addr;
  char *filter_expr;

  if(argc < 2) {
    fprintf(stderr, "[ERROR]: No mac address provided!\n");
    fprintf(stderr, "\t Usage: %s <mac addr>\n\n", argv[0]);
    exit(99);
  }
  my_mac_addr = argv[1];

  // build the filter expression
  filter_expr = build_filter_expr("eth0", my_mac_addr, 0);

  // Grab the pcap device for the interface.
  handle = find_pcap_dev("eth0", &addr, filter_expr);

  // loop over packets until we are done
  while((rc = pcap_next_ex(handle, &hdr, &pkt)) >= 0) {
    eth_hdr = (struct ether_header *)pkt;
    if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
      printf("Got an IP packet, parsing...\n");
      parse_ip(pkt, my_mac_addr, handle, hdr->len);
    } else {
      print_err("Got an unknow packet, what to do?\n");
    }
  }

  if(rc == -1) {
    print_err("Error capturing packets: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
