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
#include <sys/random.h>

#include "log.h"
#include "sock_util.h"
#include "tun_util.h"
#include "vpnclient.h"
#include "util.h"
#include "clhash.h"

#define VPN_SERVER_IP "55.132.14.5"
#define VPN_SERVER_PORT 9090

#define BUFFSIZE 2000
#define SECRET_WORD "sandya is cool"
int seq_num = 0;
int session_num;

int
check_checksum(struct WireChild *wc, size_t payload_len)
{
    uint16_t received_chksum = wc->checksum;
    wc->checksum = 0;
    uint16_t computed_chksum = chksum((uint16_t *)wc, sizeof(struct WireChild) + payload_len);
    return received_chksum == computed_chksum;
}

int
perform_handshake(int sockfd, struct sockaddr_in *server)
{
    // Default to 0 initially so that you can test, but probably want to address
    // this during the implementation.
    
    // =======STEP 1========
    // Generate Nonce
    size_t nonce_size = 4;
    char client_nonce[nonce_size];

    if (getrandom(client_nonce, nonce_size, 0) != nonce_size){
        perror("getrandom");
        return -1;
    }

    // insert msg into payload of pkt
    void* pkt = malloc(sizeof (struct WireChild) + nonce_size);
    struct WireChild* wc = (struct WireChild*)pkt;
    wc->W = 'W';
    wc->C = 'C';
    wc->version = 0x01;
    wc->type = HELLO;
    wc->length = ntohs(sizeof(struct WireChild) + nonce_size);
    wc->checksum = 0;
    wc->seq_num = seq_num++;
    wc->session_id = 0; // TODO no session id yet?
    wc->unused = 0; // reserved for future use
    memcpy(pkt + sizeof(struct WireChild), client_nonce, nonce_size);

    // compute checksum
    wc->checksum = chksum((uint16_t *)pkt, sizeof(struct WireChild) + nonce_size);

    // Send pkt
    // ssize_t sent = sendto(sockfd, pkt, sizeof(struct WireChild) + nonce_size, 0, (struct sockaddr *)server, sizeof(struct sockaddr_in));
    ssize_t sent = send(sockfd, pkt, sizeof(struct WireChild) + nonce_size, 0);
    if (sent != sizeof(struct WireChild) + nonce_size){
        perror("send");
        free(pkt);
        return -1;
    }
    free(pkt);


    // =======STEP 2========
    void *pkt2 = malloc(sizeof(struct WireChild) + nonce_size);
    // Receive Server_nonce pkt
    // ssize_t received_bytes = recvfrom(sockfd, pkt2, sizeof(struct WireChild) + nonce_size, 0, (struct sockaddr *)server, (socklen_t *) sizeof(struct sockaddr_in));
    ssize_t received_bytes = recv(sockfd, pkt2, sizeof(struct WireChild) + nonce_size, 0);
    if (received_bytes < 0){
        perror("recv");
        free(pkt2);
        return -1;
    }

    // Read server_nonce pkt into buffer
    struct WireChild* wc2 = (struct WireChild*)pkt2;
    if (wc2->type != CHALLENGE || wc2->seq_num != seq_num - 1){
        print_err("Expected CHALLENGE packet, got type 0x%02x\n", wc2->type);
        free(pkt2);
        return -1;
    }

    if (!check_checksum(wc2, nonce_size)){
        print_err("Invalid checksum for CHALLENGE packet\n");
        free(pkt2);
        return -1;
    }

    char server_nonce[nonce_size];
    memcpy(server_nonce, pkt2 + sizeof(struct WireChild), nonce_size);
    free(pkt2);


    // =======STEP 3========
    // Compute hash
    void *secret = malloc(strlen(SECRET_WORD));
    memcpy(secret, SECRET_WORD, strlen(SECRET_WORD));

    char hash_input[2 * nonce_size];
    memcpy(hash_input, client_nonce, nonce_size);
    memcpy(hash_input + nonce_size, server_nonce, nonce_size);

    uint64_t hashed = clhash(secret, hash_input, 2 * nonce_size);

    // Send response type hash
    void *pkt3 = malloc(sizeof(struct WireChild) + sizeof(uint64_t));
    struct WireChild* wc3 = (struct WireChild*)pkt3;
    wc3->W = 'W';
    wc3->C = 'C';
    wc3->version = 0x01;
    wc3->type = RESPONSE;
    wc3->length = ntohs(sizeof(struct WireChild) + sizeof(uint64_t));
    wc3->checksum = 0;
    wc3->seq_num = seq_num++;
    wc3->session_id = 0; // TODO no session id yet?
    wc3->unused = 0; // reserved for future use
    memcpy(pkt3 + sizeof(struct WireChild), &hashed, sizeof(uint64_t));

    // compute checksum
    wc3->checksum = chksum((uint16_t *)pkt3, sizeof(struct WireChild) + sizeof(uint64_t));

    // Send pkt
    // ssize_t sent = sendto(sockfd, pkt3, sizeof(struct WireChild) + sizeof(uint64_t), 0, (struct sockaddr *)server, sizeof(struct sockaddr_in));
    ssize_t sent = send(sockfd, pkt3, sizeof(struct WireChild) + sizeof(uint64_t), 0);
    if (sent != sizeof(struct WireChild) + sizeof(uint64_t)){
        perror("send");
    }
    free(pkt3);

    // updates session id
    memcpy(&session_num, &hashed, sizeof(int));


    // =======STEP 4========
    // Receive ACK
    void *pkt4 = malloc(sizeof(struct WireChild));
    // Receive Server_nonce pkt
    // received_bytes = recvfrom(sockfd, pkt4, sizeof(struct WireChild), 0, (struct sockaddr *)server, (socklen_t *) sizeof(struct sockaddr_in));
    ssize_t received_bytes = recv(sockfd, pkt4, sizeof(struct WireChild), 0);
    if (received_bytes < 0){
        perror("recv");
    }

    // Read server_nonce pkt into buffer
    struct WireChild* wc4 = (struct WireChild*)pkt4;
    if (wc4->type != ACK || wc4->seq_num != seq_num - 1){
        print_err("Expected ACK packet, got type 0x%02x\n", wc4->type);
        free(pkt4);
        return -1;
    }

    if (!check_checksum(wc4, 0)){
        print_err("Invalid checksum for ACK packet\n");
        free(pkt4);
        return -1;
    }

    free(pkt4);

    // close(sockfd);

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
 
