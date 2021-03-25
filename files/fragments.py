#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message in multiple fragments """

__author__      = "Bonzon Tiffany & Thoeny Laurent"

from scapy.all import *
import binascii
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# We use 0 as the IV for this example (on 24 bits)
iv = b'\x00\x00\x00'

# Initialize the seed from the IV and the key
seed = iv + key

# We use the same message as the decryption example
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'

# We split the message in three fragments of equal size
fragments = (message[:12], message[12:24], message[24:])

# Using RC4 
cipher = RC4(seed, streaming=False)

# As hinted we use the existing ARP example to craft our own
template = rdpcap('arp.cap')[0]

count = 0

for frag in fragments:
    icv = binascii.crc32(frag).to_bytes(4, byteorder='little')
    ct = cipher.crypt(frag + icv)

    # We update our template with the fragment values
    template.SC = count
    template.wepdata = ct[:-4]
    template.iv = iv
    template.icv = struct.unpack('!L', ct[-4:])[0]
    
    # We verify if there should be more fragments
    template.FCfield.MF = (count != 2)#fragments.len)

    # We need this for the fragment size to be calculated properly
    template[RadioTap].len = None

    # Finally we export the fragment to our .cap file
    wrpcap('arp3.cap', template, append = True)    
    count += 1
