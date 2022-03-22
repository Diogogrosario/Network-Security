#!/usr/bin/env python3

from scapy.all import * 
import time

a = IP()
a.dst = '142.250.200.142'
counter = 1
while(counter < 10):
    a.ttl = counter
    counter += 1
    b = ICMP()
    p = a/b
    send(p)
    time.sleep(1)