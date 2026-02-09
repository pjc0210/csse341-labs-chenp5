// SPDX-License-Identifier: Unlicense

#ifndef _UTIL_H
#define _UTIL_H

// forward declarations
#include <stdint.h>
struct tcphdr;
struct iphdr;
struct timeval;

#define NS_UTIL_BUFSIZE 512

/**
 * fmt_ts()
 *
 * Format a timestamp obtained from a pcap packet header.
 *
 * @param ts    The timeval to format.
 *
 * @return the formatted string if successful, 0 otherwise.
 */
char *fmt_ts(struct timeval *ts);

/**
 * mac_to_str()
 *
 * Format a MAC address as a string.
 *
 * @param addr  The MAC address to format
 *
 * @return A string representing the mac address.
 *
 *  WARNING:
 *  =======
 *    THIS FUNCTION RETURNS A STATIC STRING, SO COPY IT IF YOU NEED IT
 *    TO PERSIST. CALLS TO THIS FUNCTION WILL OVERWRITE PREVIOUS STRINGS.
 */
char *mac_to_str(void *addr);

/**
 * ip_to_str()
 *
 * Format an IPv4 address as a string.
 *
 * @param addr  The IPv4 address to format
 *
 * @return A string representing the IPv4 address.
 *
 *  WARNING:
 *  =======
 *    THIS FUNCTION RETURNS A STATIC STRING, SO COPY IT IF YOU NEED IT
 *    TO PERSIST. CALLS TO THIS FUNCTION WILL OVERWRITE PREVIOUS STRINGS.
 */
char *ip_to_str(void *addr);

/**
 * Compute the checksum of a given header.
 *
 * @param hdr  The header to compute the checksum for.
 * @param len  The length of the header in bytes.
 *
 * @return the computed checksum.
 */
uint16_t chksum(uint16_t *hdr, uint32_t len);

/**
 * Set a signal handler given a signal number.
 *
 * @param signum The signal number for the signal to catch.
 * @param handler  The signal's handler function.
 */
void setsighandler(int signum, void (*handler)(int));

#endif // util.h
