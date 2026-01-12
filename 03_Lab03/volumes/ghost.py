#!/usr/bin/env python3
from scapy.all import *

ghost_ip = "10.10.0.10"

def ghost_response(pkt):
    my_mac = get_if_hwaddr("eth0")
    if ARP in pkt and pkt[ARP].op == 1:  # who-has (request)
        ether = Ether(dst=pkt[Ether].src, src=my_mac)
        arp = ARP(op=2, hwsrc=my_mac, psrc=ghost_ip,
                  hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)

        response = ether / arp
        sendp(response, iface=pkt.sniffed_on, verbose=0)

    elif ICMP in pkt and pkt[ICMP].type == 8: # Echo (ping) request
        # pkt.show()
        raw_data = pkt[Raw].load
        ip = IP(src=ghost_ip, dst=pkt[IP].src)
        icmp = ICMP(type=0, code=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        response = ip / icmp / raw_data
        send(response, verbose=0)

def show_pkt(pkt):
    pkt.show()

def main():
    sniff(iface='eth0', filter="(arp or icmp) and dst host 10.10.0.10", prn=ghost_response)
    # sniff(iface='eth0', filter='arp', prn=show_pkt)

if __name__ == "__main__":
    main()