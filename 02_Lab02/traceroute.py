#!/usr/bin/env python3
from scapy.all import *
import sys
import socket
import time
import struct

def traceroute(dest, max_hops=30, timeout=2):
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=dest, ttl=ttl) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply is None:
            print(f"{ttl}\t*")
        elif reply.type == 0:
            print(f"{ttl}\t{reply.src} (Reached)")
            break
        else:
            print(f"{ttl}\t{reply.src}")

def main():
    destination = "1.1.1.1" # sys.argv[1]
    traceroute(destination)

if __name__ == "__main__":
    main()
    # pkt = sniff(iface='eth0', filter='icmp', count=1)