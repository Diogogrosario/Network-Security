from scapy.all import *
    
def print_pkt(pkt):
    pkt.show()
    if(pkt.getlayer(ICMP).type == 8):
        a = IP(src = pkt[IP].dst, dst = pkt[IP].src, ihl=pkt[IP].ihl)
        b = ICMP(type=0,id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        p = a/b/data
        send(p)
    
#iface=['br-fd2d696261de', 'enp0s3']
filter1 = 'icmp'
filter2 = 'tcp and port 23 and host 10.9.0.6'
filter3 = "net 10.9.0.0/24"
pkt = sniff(iface = ['br-fd2d696261de','enp0s3'], filter=filter1, prn=print_pkt)