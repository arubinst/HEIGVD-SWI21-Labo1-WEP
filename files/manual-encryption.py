#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__     = "Abraham Rubinstein, Laurent Scherer"
__copyright__  = "Copyright 2017, HEIG-VD"
__license__    = "GPL"
__version__    = "1.0"
__email__      = "abraham.rubinstein@heig-vd.ch, laurent.scherer@heig-vd.ch"
__status__     = "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
import zlib



# lecture de message chiffré - rdpcap retourne toujours un array, même si 
# la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# Message originel, derniers bytes modifiés par 0xffffff
plaintext = b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xff\xff\xff"


#IV 000 ; Cle wep AA:AA:AA:AA:AA
IV   = b'\x00\x00\x00'
key  = b'\xaa\xaa\xaa\xaa\xaa'
# rc4 seed est composée de IV+clé
seed = IV + key


# Calcule de CRC32
# print(struct.pack("<I",int(zlib.crc32(plaintext))))
icv = struct.pack("<I",int(zlib.crc32(plaintext)))


# chiffrement rc4
cipher = RC4(seed, streaming=False)
ciphertext = cipher.crypt(plaintext + icv)


# création du payload
arp.wepdata = ciphertext[:-4]
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
arp.iv = IV

# sauvegarde vers un nouveau pcap
wrpcap('arp2.cap', arp)
