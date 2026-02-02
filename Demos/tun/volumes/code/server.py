#!/usr/bin/python3

import socket
from scapy.all import *

SERVER_IP = "10.10.0.5"
SERVER_PORT = 1234

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))

    while True:
        data, (ip, port) = sock.recvfrom(2048)
        pkt = IP(data)
        print(f"{ip}:{port} --> {SERVER_IP}:{SERVER_PORT}")
        print(f"   Inside: {pkt.src} --> {pkt.dst}")
