// SPDX-License-Identifier: Unlicense

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

#include "util.h"

char *
fmt_ts(struct timeval *ts)
{
  static char fmtstr[NS_UTIL_BUFSIZE];
  char *str = fmtstr;
  struct tm *ltime;
  time_t local_tv_sec;

  local_tv_sec = ts->tv_sec;
  ltime        = localtime(&local_tv_sec);
  str += strftime(fmtstr, sizeof fmtstr, "%H:%M:%S", ltime);

  snprintf(str, NS_UTIL_BUFSIZE - strlen(fmtstr), ".%.6ld", ts->tv_usec);
  return fmtstr;
}

char *
mac_to_str(void *addr)
{
  // Adapted from https://stackoverflow.com/a/4738943
  static char buf[18];
  struct ether_addr *eth_addr = (struct ether_addr *)addr;

  sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", eth_addr->ether_addr_octet[0],
          eth_addr->ether_addr_octet[1], eth_addr->ether_addr_octet[2],
          eth_addr->ether_addr_octet[3], eth_addr->ether_addr_octet[4],
          eth_addr->ether_addr_octet[5]);
  return buf;
}

char *
ip_to_str(void *addr)
{
  struct in_addr *iaddr = (struct in_addr *)addr;
  return inet_ntoa(*iaddr);
}
