// SPDX-License-Identifier: Unlicense

#include <errno.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "sock_util.h"
#include "tun_util.h"
#include "util.h"
#include "vpnserver.h"
#include "clhash.h"

#define BUFFSIZE 2000
#define SECRET_WORD "sandya is cool"
int session_num;

void
srv_tun_callback(int tunfd, int sockfd, struct sockaddr_in *client)
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
  sent = sendto(sockfd, pkt, pktlen, 0, (struct sockaddr *)client,
                sizeof(*client));
  if(sent < pktlen || sent < 0) {
    print_err("Sending TUN packet on UDP socket had some errors\n");
    if(sent < 0)
      perror("sendto");
  }
}

void
srv_sock_callback(int tunfd, int sockfd, struct sockaddr_in *client)
{
  unsigned char pkt[BUFFSIZE];
  ssize_t pktlen    = 0;
  socklen_t addrlen = sizeof(struct sockaddr_in);

  print_log("Received packet on UDP socket!\n");

  bzero(pkt, BUFFSIZE);
  pktlen =
      recvfrom(sockfd, pkt, BUFFSIZE, 0, (struct sockaddr *)client, &addrlen);
  if(pktlen < 0) {
    print_err("Error reading packet from UDP socket: %s\n", strerror(errno));
    return;
  }
  // TODO:
  // =====
  // Packet received on the UDP socket, what should we do with it?
  struct WireChild *wc = (struct WireChild *)pkt;
  print_log("Received packet with type 0x%02x and length %d\n", wc->type, wc->length);

  // Write something to the TUN interface to appear as if it was just received
  // there. That means the kernel will now route it to the right application.
  pktlen = write(tunfd, pkt, pktlen);
  if(pktlen < 0) {
    print_err("Error writing data to the TUN interface: %s\n", strerror(errno));
  }
}

int
check_checksum(struct WireChild *wc, size_t payload_len)
{
    uint16_t received_chksum = wc->checksum;
    wc->checksum = 0;
    uint16_t computed_chksum = chksum((uint16_t *)wc, sizeof(struct WireChild) + payload_len);
    return received_chksum == computed_chksum;
}

int
lsn_handshake(int sockfd, struct sockaddr_in *client)
{
    size_t nonce_size = 4;
    int seq_num;

    ssize_t sent = 0;
    ssize_t received_bytes = 0;

    // =======STEP 1========
    // Receive client_nonce packet
    void *pkt = malloc(sizeof(struct WireChild) + nonce_size);

    // Receive Server_nonce pkt
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    received_bytes = recvfrom(sockfd, pkt, sizeof(struct WireChild) + nonce_size, 0, (struct sockaddr *)client, &client_addr_len);

    if (received_bytes < 0){
        perror("recvfrom");
        free(pkt);
        return -1;
    }

    // connect to client
    if (connect(sockfd, (struct sockaddr *)client, sizeof(struct sockaddr_in)) < 0) {
        perror("connect");
        free(pkt);
        return -1;
    }

    struct WireChild* wc = (struct WireChild*)pkt;
    if (wc->type != HELLO || wc->seq_num != 0){
        print_err("Expected HELLO packet, got type 0x%02x\n", wc->type);
        free(pkt);
        return -1;
    }

    if (!check_checksum(wc, nonce_size)){
        print_err("Invalid checksum for HELLO packet\n");
        free(pkt);
        return -1;
    }

    // Save client_nonce
    char client_nonce[nonce_size];
    memcpy(client_nonce, pkt + sizeof(struct WireChild), nonce_size);
    seq_num = wc->seq_num;
    free(pkt);

    // =======STEP 2========
    // Generate server nonce
    char server_nonce[nonce_size];
    if (getrandom(server_nonce, nonce_size, 0) != nonce_size){
        perror("getrandom");
        return -1;
    }

    // Send Challenge packet
    void* pkt2 = malloc(sizeof (struct WireChild) + nonce_size);
    struct WireChild* wc2 = (struct WireChild*)pkt2;
    wc2->W = 'W';
    wc2->C = 'C';
    wc2->version = 0x01;
    wc2->type = CHALLENGE;
    wc2->length = ntohs(sizeof(struct WireChild) + nonce_size);
    wc2->checksum = 0;
    wc2->seq_num = seq_num;
    wc2->session_id = 0; // no session id yet
    wc2->unused = 0; // reserved for future use
    memcpy(pkt2 + sizeof(struct WireChild), server_nonce, nonce_size);

    // compute checksum
    wc2->checksum = chksum((uint16_t *)pkt2, sizeof(struct WireChild) + nonce_size);

    // Send pkt
    ssize_t sent = sendto(sockfd, pkt2, sizeof(struct WireChild) + nonce_size, 0, (struct sockaddr *)client, &client_addr_len);
    // sent = send(sockfd, pkt2, sizeof(struct WireChild) + nonce_size, 0);
    if (sent != sizeof(struct WireChild) + nonce_size){
        perror("sendto");
        free(pkt2);
        return -1;
    }
    free(pkt2);

    // =======STEP 3========
    // Receive client_response
    void *pkt3 = malloc(sizeof(struct WireChild) + nonce_size);
    // Receive Server_nonce pkt
    received_bytes = recvfrom(sockfd, pkt3, sizeof(struct WireChild) + nonce_size, 0, (struct sockaddr *)client, &client_addr_len);
    // received_bytes = recv(sockfd, pkt3, sizeof(struct WireChild) + nonce_size, 0);

    if (received_bytes < 0){
        perror("recvfrom");
        free(pkt3);
        return -1;
    }

    struct WireChild* wc3 = (struct WireChild*)pkt3;
    if (wc3->type != RESPONSE || wc3->seq_num != seq_num + 1){
        print_err("Expected RESPONSE packet, got type 0x%02x\n", wc3->type);
        free(pkt3);
        return -1;
    }
    
    if (!check_checksum(wc3, sizeof(uint64_t))){
        print_err("Invalid checksum for RESPOND packet\n");
        free(pkt3);
        return -1;
    }

    // Verify client hash
    uint64_t client_hash;
    memcpy(&client_hash, pkt3 + sizeof(struct WireChild), sizeof(uint64_t));
    seq_num = wc3->seq_num;
    free(pkt3);

    // Compute expected hash
    void *secret = malloc(strlen(SECRET_WORD));
    memcpy(secret, SECRET_WORD, strlen(SECRET_WORD));

    char hash_input[2 * nonce_size];
    memcpy(hash_input, client_nonce, nonce_size);
    memcpy(hash_input + nonce_size, server_nonce, nonce_size);
    uint64_t expected_hash = clhash(secret, hash_input, 2 * nonce_size);

    if (client_hash != expected_hash){
        print_err("Client hash does not match expected hash\n");

        void *pkt4 = malloc(sizeof(struct WireChild));
        struct WireChild* wc4 = (struct WireChild*)pkt4;
        wc4->W = 'W';
        wc4->C = 'C';
        wc4->version = 0x01;
        wc4->type = ERROR;
        wc4->length = ntohs(sizeof(struct WireChild));
        wc4->checksum = 0;
        wc4->seq_num = seq_num;
        wc4->session_id = session_num;
        wc4->unused = 0; // reserved for future use
        
        // compute checksum
        wc4->checksum = chksum((uint16_t *)pkt4, sizeof(struct WireChild));

        // Send pkt
        sent = sendto(sockfd, pkt4, sizeof(struct WireChild), 0, (struct sockaddr *)client, &client_addr_len);
        // sent = send(sockfd, pkt4, sizeof(struct WireChild), 0);
        if (sent != sizeof(struct WireChild)){
            perror("sendto");
            free(pkt4);
            return -1;
        }

        free(pkt4);
        return -1;
    }

    // updates session id
    memcpy(&session_num, &expected_hash, sizeof(int));


    // =======STEP 4========
    // Send ACK response
    void *pkt4 = malloc(sizeof(struct WireChild));
    struct WireChild* wc4 = (struct WireChild*)pkt4;
    wc4->W = 'W';
    wc4->C = 'C';
    wc4->version = 0x01;
    wc4->type = ACK;
    wc4->length = ntohs(sizeof(struct WireChild));
    wc4->checksum = 0;
    wc4->seq_num = seq_num;
    wc4->session_id = session_num;
    wc4->unused = 0; // reserved for future use

    // compute checksum
    wc4->checksum = chksum((uint16_t *)pkt4, sizeof(struct WireChild));

    // Send pkt
    sent = sendto(sockfd, pkt4, sizeof(struct WireChild), 0, (struct sockaddr *)client, &client_addr_len);
    // sent = send(sockfd, pkt4, sizeof(struct WireChild), 0);
    if (sent != sizeof(struct WireChild)){
        perror("sendto");
        free(pkt4);
        return -1;
    }
    free(pkt4);

    // close(sockfd);

    return 0;
}

int
main(int argc, char **argv)
{
  char ifname[IFNAMSIZ];
  int tunfd, sockfd;
  struct sockaddr_in client_addr;
  fd_set readfds; // we use a set of file descriptors for listening to both

  // alloc a TUN device
  strncpy(ifname, "tun0", IFNAMSIZ);
  if((tunfd = tun_alloc(ifname)) < 0) {
    print_err("Failed to create TUN device!\n");
    exit(EXIT_FAILURE);
  }
  print_log("Created TUN dev %s\n", ifname);

  // connect to the server's UDP socket
  sockfd = bind_udp_sock("0.0.0.0", 9090);
  if(sockfd < 0) {
    print_err("Failed to bind to a UDP socket on port %d\n", 9090);
    close(tunfd);
    exit(EXIT_FAILURE);
  }

  // This is the client's main loop.
  //  For this project, the client can only do one session at a time.
  //  So we always start with establishing a session and then move into the
  //  session loop of going through the TUN and socket.
  while(1) {
    if(lsn_handshake(sockfd, &client_addr)) {
      // if failed, stop and tryi again.
      print_err("Handshake with client failed!\n");
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
        srv_tun_callback(tunfd, sockfd, &client_addr);
      }

      // don't put this in an else statement because both might be set.
      if(FD_ISSET(sockfd, &readfds)) {
        srv_sock_callback(tunfd, sockfd, &client_addr);
      }
    }
  }
  return EXIT_SUCCESS;
}
