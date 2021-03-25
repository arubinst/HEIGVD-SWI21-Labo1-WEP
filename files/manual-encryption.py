#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message """

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

# We calculate the ICV using binascii for the CRC32
# Convertion par magie selon : https://docs.python.org/3/library/stdtypes.html#int.to_bytes
icv = binascii.crc32(message).to_bytes(4, byteorder='little')


# Using RC4 
cipher = RC4(seed, streaming=False)
ct = cipher.crypt(message + icv)

# As hinted we use the existing ARP example to craft our own
template = rdpcap('arp.cap')[0]
template.wepdata = ct[:-4]
template.iv = iv
template.icv = struct.unpack('!L', ct[-4:])[0]

# On exporte à nouveau dans un fichier .cap
wrpcap('arp2.cap', template)