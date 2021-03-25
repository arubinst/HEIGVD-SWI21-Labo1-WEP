#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message with a WEP key"""

__author__      = "Robin Cuénoud Florian Mülhauser"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
import binascii

from scapy.layers.l2 import ARP

from rc4 import RC4
#Cle wep FF:FF:FF:FF:FF
key= b'\xff\xff\xff\xff\xff'

# import pour avoir un modèle
arp = rdpcap('arp.cap')[0]



# frame copiée depuis wireshark
cleartext =  b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01" \
b"\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\xff\x00\x00\x00\x00\x00\x00" \
b"\xc0\xa8\x02\xff"

iv = b"\x0c\x4d\x5c"

print(arp.iv.hex())
clear_icv = binascii.crc32(cleartext).to_bytes(4,byteorder='little')
# rc4 seed est composé de IV+clé
seed = iv+key

# chiffrement RC4
cipher = RC4(seed, streaming=False)

ciphertext=cipher.crypt(cleartext + clear_icv)

# le ICV est les derniers 4 octets - je le passe en format Long big endian
arp.wepdata = ciphertext[:-4]
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

wrpcap("created_arp.cap", arp)


sendp(arp)
