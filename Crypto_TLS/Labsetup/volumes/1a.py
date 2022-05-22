#!/usr/bin/env python3

import socket
import ssl
import sys
import pprint

hostname = sys.argv[1]
port = 443
cadir = '/etc/ssl/certs'
#cadir = './client-certs'

# Set up the TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # For Ubuntu 20.04 VM

context.load_verify_locations(capath=cadir)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

# Create TCP connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))
input("After making TCP connection. Press any key to continue ...")

# Add the TLS
ssock = context.wrap_socket(sock, server_hostname=hostname,
                            do_handshake_on_connect=False)
ssock.do_handshake()   # Start the handshake
print("=== Cipher used: {}".format(ssock.cipher()))
print("=== Server hostname: {}".format(ssock.server_hostname))
print("=== Server certificate:")
pprint.pprint(ssock.getpeercert())
pprint.pprint(context.get_ca_certs())
input("After TLS handshake. Press any key to continue ...")

# Close the TLS Connection
ssock.shutdown(socket.SHUT_RDWR)
ssock.close()


# Answers
# Cipher used: ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)

'''
Certificate: 
{'OCSP': ('http://GEANT.ocsp.sectigo.com',),
 'caIssuers': ('http://GEANT.crt.sectigo.com/GEANTOVRSACA4.crt',),
 'crlDistributionPoints': ('http://GEANT.crl.sectigo.com/GEANTOVRSACA4.crl',),
 'issuer': ((('countryName', 'NL'),),
            (('organizationName', 'GEANT Vereniging'),),
            (('commonName', 'GEANT OV RSA CA 4'),)),
 'notAfter': 'Mar 14 23:59:59 2023 GMT',
 'notBefore': 'Mar 14 00:00:00 2022 GMT',
 'serialNumber': '1B7146CF7A74B5F84D38D6389221B618',
 'subject': ((('countryName', 'PT'),),
             (('stateOrProvinceName', 'Porto'),),
             (('organizationName', 'Universidade do Porto'),),
             (('commonName', 'fe.up.pt'),)),
 'subjectAltName': (('DNS', 'fe.up.pt'), ('DNS', 'www.fe.up.pt')),
 'version': 3}
'''

'''
Certs:
 Common CA certificates
Contains CA certificates to allow SSL-based
applications to check for the authenticity of SSL connections.
It includes, among others, certificate authorities.
'''

