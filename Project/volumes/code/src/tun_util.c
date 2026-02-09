// SPDX-License-Identifier: Unlicense

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "log.h"
#include "tun_util.h"

int
tun_alloc(char *dev)
{
  int fd         = -1;
  size_t namelen = 0;
  struct ifreq iff_request;

  // check on the size of the name
  namelen = strlen(dev);
  if(namelen >= IFNAMSIZ) {
    print_err("Invalid device name %s to tun_alloc", dev);
    errno = EINVAL;
    return -1;
  }

  if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    print_err("Failde to open the TUN device: %s\n", strerror(errno));
    return -1;
  }

  memset(&iff_request, 0, sizeof iff_request);
  /*
   * IFF_TUN: TUN device, do not grab Ethernet headers.
   *
   * IFF_NO_PI: Do no include packet information, we grab them form the header.
   */
  iff_request.ifr_flags = IFF_TUN | IFF_NO_PI;
  memcpy(iff_request.ifr_name, dev, namelen);
  if(ioctl(fd, TUNSETIFF, (void *)&iff_request) < 0) {
    print_err("Error on getting TUN device %s: %s\n", dev, strerror(errno));
    close(fd);
    return -1;
  }

  // Copy the name of the interface out
  memcpy(dev, iff_request.ifr_name, IFNAMSIZ);

  return fd;
}
