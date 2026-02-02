#!/usr/bin/python3

import fcntl
import struct
import os
import socket
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

VPN_SERVER_IP = "10.10.0.5"
VPN_SERVER_PORT = 1234

def setup_tun_iface():
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
    ifname = ifname_bytes.decode('UTF-8')[:16].strip('\x00')

    os.system(f"ip addr add 192.123.137.10/24 dev {ifname}")
    os.system(f"ip link set dev {ifname} up")
    os.system(f"ip route add 192.123.137.0/24 dev {ifname}")

    return tun, ifname


def parse_pkt(packet, sock):
    # ip = IP(packet)
    # ip.show()

    # Make the original packet a payload of the next one
    sock.sendto(packet, (VPN_SERVER_IP, VPN_SERVER_PORT))

def connect_vpn_server():
    # createa UDP socket to the VPN server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return sock

if __name__ == '__main__':
    tun, ifname = setup_tun_iface()
    print(f"The interface name is: {ifname}")
    sock = connect_vpn_server()

    while True:
        packet = os.read(tun, 2048)
        if True:
            parse_pkt(packet, sock)
