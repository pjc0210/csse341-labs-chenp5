// SPDX-License-Identifier: Unlicense

#include <errno.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "sock_util.h"
#include "tun_util.h"
#include "vpnclient.h"

#define VPN_SERVER_IP "55.132.14.5"
#define VPN_SERVER_PORT 9090

#define BUFFSIZE 2000

int
perform_handshake(int sockfd, struct sockaddr_in *server)
{
  // Default to 0 initially so that you can test, but probably want to address
  // this during the implementation.
  return 0;
}

void
tun_callback(int tunfd, int sockfd, struct sockaddr_in *server)
{
  unsigned char pkt[BUFFSIZE];
  ssize_t pktlen = 0;
  ssize_t sent   = 0;

  print_log("Received packet on TUN interface!\n");

  bzero(pkt, BUFFSIZE);
  pktlen = read(tunfd, pkt, BUFFSIZE);
  if(pktlen < 0) {
    print_err("Packet read on TUN interface failed: %s\n", strerror(errno));
    return;
  }

  // TODO:
  // =====
  // What should happen when you receive a packet on the TUN interface?

  // send something out on the UDP socket, for now, will just send out whatever
  // we receive
  sent = sendto(sockfd, pkt, pktlen, 0, (struct sockaddr *)server,
                sizeof(*server));
  if(sent < pktlen || sent < 0) {
    print_err("Sending TUN packet on UDP socket had some errors\n");
    if(sent < 0)
      perror("sendto");
  }
}

void
sock_callback(int tunfd, int sockfd, struct sockaddr_in *server)
{
  unsigned char pkt[BUFFSIZE];
  ssize_t pktlen = 0;

  print_log("Received packet on UDP socket!\n");

  bzero(pkt, BUFFSIZE);
  pktlen = recvfrom(sockfd, pkt, BUFFSIZE, 0, NULL, NULL);
  if(pktlen < 0) {
    print_err("Error reading packet from UDP socket: %s\n", strerror(errno));
    return;
  }
  // TODO:
  // =====
  // Packet received on the UDP socket, what should we do with it?

  // Write something to the TUN interface to appear as if it was just received
  // there. That means the kernel will now route it to the right application.
  pktlen = write(tunfd, pkt, pktlen);
  if(pktlen < 0) {
    print_err("Error writing data to the TUN interface: %s\n", strerror(errno));
  }
}

int
main(int argc, char **argv)
{
  char ifname[IFNAMSIZ];
  int tunfd, sockfd;
  struct sockaddr_in server_addr;
  fd_set readfds; // we use a set of file descriptors for listening to both

  // alloc a TUN device
  strncpy(ifname, "tun0", IFNAMSIZ);
  if((tunfd = tun_alloc(ifname)) < 0) {
    print_err("Failed to create TUN device!\n");
    exit(EXIT_FAILURE);
  }
  print_log("Created TUN dev %s\n", ifname);

  // connect to the server's UDP socket
  sockfd = connect_udp_sock(VPN_SERVER_IP, VPN_SERVER_PORT, &server_addr);
  if(sockfd < 0) {
    print_err("Failed to connect to VPN server (%s, %d)!", VPN_SERVER_IP,
              VPN_SERVER_PORT);
    close(tunfd);
    exit(EXIT_FAILURE);
  }

  // This is the client's main loop.
  //  For this project, the client can only do one session at a time.
  //  So we always start with establishing a session and then move into the
  //  session loop of going through the TUN and socket.
  while(1) {
    if(perform_handshake(sockfd, &server_addr)) {
      // if failed, stop and tryi again.
      print_err("Handshake with server failed!\n");
      continue;
    }

    // TODO:
    // ====
    //   For now this will only do one session and stay there forever, you'd
    //   probably want to think about how and when to escape this loop.
    while(1) {
      // initialize the set of file descriptors
      // NOTE:
      // =====
      //   You have to do this set clearing and creation every time since the
      //   select system call will change readfds.
      FD_ZERO(&readfds);
      FD_SET(sockfd, &readfds);
      FD_SET(tunfd, &readfds);

      // use the select system call to monitor both interfaces and then get a
      // call back once EITHER of them receives any data.
      if(select(FD_SETSIZE, &readfds, NULL, NULL, NULL) < 0) {
        print_err("select failure: %s\n", strerror(errno));
        break;
      }

      if(FD_ISSET(tunfd, &readfds)) {
        tun_callback(tunfd, sockfd, &server_addr);
      }

      // don't put this in an else statement because both might be set.
      if(FD_ISSET(sockfd, &readfds)) {
        sock_callback(tunfd, sockfd, &server_addr);
      }
    }
  }
}
