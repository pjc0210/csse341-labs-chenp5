// SPDX-License-Identifier: Unlicense

#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "log.h"
#include "pcap_util.h"

pcap_t *
find_pcap_dev(char *iface, struct in_addr *in_addr, const char *filter_expr)
{
  pcap_if_t *alldevp, *p;
  pcap_t *handle = 0;
  struct bpf_program filter;
  char errbuf[PCAP_ERRBUF_SIZE];

  if(pcap_findalldevs(&alldevp, iface)) {
    print_err("Could not find any suitable interface: %s\n", iface);
    exit(EXIT_FAILURE);
  }

  // search for the interface
  for(p = alldevp; p && strncmp(p->name, iface, strlen(p->name)); p = p->next)
    ;
  if(!p) {
    print_err("Cound not find interface with name: %s\n", iface);
    goto clean_exit;
  }

  // get the handle open.
  print_log("Starting sniffer on interface %s\n", iface);
  handle =
      pcap_open_live(p->name, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1, errbuf);
  if(!handle) {
    print_err("Unable to open the adapter on iface %s: %s\n", iface, errbuf);
    goto clean_exit;
  }

  // check if should store the IPv4 address
  if(in_addr) {
    for(pcap_addr_t *a = p->addresses; p; p = p->next) {
      if(a->addr->sa_family == AF_INET) {
        memcpy(in_addr, &((struct sockaddr_in *)(a->addr))->sin_addr,
               sizeof(struct in_addr));
        break;
      }
    }
  }

  if(filter_expr) {
    // compile the filter.
    if(pcap_compile(handle, &filter, filter_expr, 0, PCAP_NETMASK_UNKNOWN)) {
      print_err("Bad filter expression - %s: %s\n", filter_expr,
                pcap_geterr(handle));
      pcap_close(handle);
      handle = 0;
      goto clean_exit;
    }

    // set the filter
    if(pcap_setfilter(handle, &filter)) {
      print_err("Error setting the filter - %s\n", pcap_geterr(handle));
      pcap_close(handle);
      handle = 0;
      goto clean_exit;
    }
  }

  print_log("Setup done successfully and ready for listening...\n");
clean_exit:
  pcap_freealldevs(alldevp);
  return handle;
}
