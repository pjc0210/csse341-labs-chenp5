// SPDX-License-Identifier: Unlicense

#ifndef _TUN_UTIL_H
#define _TUN_UTIL_H

/**
 * Connect to an TUN interface.
 *
 *
 * @param dev  The requested device name.
 *
 * @warning
 *   This funciton will overwrite the dev string, so make sure that
 *   you do not pass a constant string.
 *
 *   dev must have at least IFNAMESIZ bytes available.
 *
 * @return the device's file descriptor on success, -1 on failure (check
 *      errno).
 */
int tun_alloc(char *dev);

#endif // tun_util.h
