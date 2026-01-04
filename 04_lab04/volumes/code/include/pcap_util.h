// SPDX-License-Identifier: Unlicense

#ifndef _PCAP_UTIL_H
#define _PCAP_UTIL_H

#include "pcap.h"

// forward declaration in case it's not in use
struct in_addr;

/**
 * find_pcap_dev() - Finds a pcap device for the interface iface.
 *
 * @param iface   The interface to search for.
 * @param in_addr An optional IP address structure to copy the iface address
 *                into.
 * @param filter_expr   An optional filter expression to use for the handler.
 *
 * @return a handler for the device if found, 0 on failure.
 */
pcap_t *find_pcap_dev(char *iface, struct in_addr *in_addr,
                      const char *filter_expr);

#endif // pcap_util.h
