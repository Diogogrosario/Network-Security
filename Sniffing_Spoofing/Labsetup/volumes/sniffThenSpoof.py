#!/usr/bin/env python3
from scapy.all import *
    
def print_pkt(pkt):
    pkt.show()
    if(pkt.getlayer(ICMP).type == 8):
        a = IP(src = pkt[IP].dst, dst = pkt[IP].src, ihl=pkt[IP].ihl)
        b = ICMP(type=0,id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        p = a/b/data
        send(p)
    
interface = ['br-fd2d696261de', 'enp0s3']
filter = 'icmp'
pkt = sniff(iface=interface, filter=filter, prn=print_pkt)