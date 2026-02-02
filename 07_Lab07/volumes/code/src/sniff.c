#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "log.h"
#include "pcap_util.h"
#include "tcp_util.h"

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
  const char *tcpfilter = "tcp and (ip src 10.10.0.5 or ip src 10.10.0.4)";

  if(argc < 2) {
    fprintf(stderr, "[ERROR]: No mac address provided!\n");
    fprintf(stderr, "\t Usage: %s <mac addr>\n\n", argv[0]);
    exit(99);
  }
  my_mac_addr = argv[1];

  // build the filter expression
  filter_expr = build_filter_expr("eth0", my_mac_addr, tcpfilter);

  // Grab the pcap device for the interface.
  handle = find_pcap_dev("eth0", &addr, filter_expr);

  // loop over packets until we are done
  while((rc = pcap_next_ex(handle, &hdr, &pkt)) >= 0) {
    eth_hdr = (struct ether_header *)pkt;
    // The filter guarantees that only TCP packets arrive here, so we're sure
    // to call parse_tcp.
    parse_tcp(pkt, my_mac_addr, handle, hdr->len);
  }

  if(rc == -1) {
    print_err("Error capturing packets: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
