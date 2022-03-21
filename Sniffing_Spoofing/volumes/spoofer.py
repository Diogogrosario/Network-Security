from scapy.all import * 
a = IP()
a.dst = '10.9.0.5'
b = ICMP()
p = a/b
send(p)