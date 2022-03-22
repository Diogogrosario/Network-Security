#!/usr/bin/env python3
from scapy.all import *
    
def print_pkt(pkt):
    pkt.show()
    
interface = ['br-fd2d696261de', 'enp0s3']
filter1 = 'icmp' 
filter2 = 'tcp and port 23 and host 10.9.0.6'
filter3 = "net 10.9.0.0/24"
pkt = sniff(iface=interface, filter=filter3, prn=print_pkt)