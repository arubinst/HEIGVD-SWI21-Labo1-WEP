#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__ = "Arthur Bécaud, Bruno Egremy"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "arthur.becaud@heig-vd.ch, bruno.egremy@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from rc4 import RC4
import binascii

# message from capture template 'arp.cap', key and a random iv
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64' \
          b'\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
key = b'\xaa\xaa\xaa\xaa\xaa'
iv = b'\x01\x23\x45'

# init rc4 with a seed (iv+key)
cipher = RC4(iv + key, streaming=False)
# compute icv
icv = binascii.crc32(message).to_bytes(4, byteorder='little')
# encrypt message+icv
ciphertext = cipher.crypt(message + icv)

# read template wireshark capture
arp = rdpcap('arp.cap')[0]
# update arp wepdata, iv and icv
arp.wepdata = ciphertext[:-4]
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
arp.iv = iv

# write new wireshark capture
wrpcap('arp-encrypted.cap', arp, append=False)
