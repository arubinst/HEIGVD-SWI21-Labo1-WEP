#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Michaël da Silva, Nenad Rajic"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "michael.dasilva@heig-vd.ch, nenad.rajic@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

# Message à utiliser dans notre paquet forgé (min. 36 caractères)
data = "HEIG-VD 2021, SWI: laboratoire 2 WEP"

# lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# Calcul du ICV + passage en bytes au format little endian
icv_numerique = binascii.crc32(data.encode()) & 0xffffffff
icv_enclair = icv_numerique.to_bytes(4, byteorder='little')

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# chiffrement rc4
cipher = RC4(seed, streaming=False)
ciphertext = cipher.crypt(data.encode() + icv_enclair)

# Corps de la trame chiffré sans l'ICV
arp.wepdata = ciphertext[:-4]

# ICV du corps de la trame chiffré au format Big endian
arp.icv = struct.unpack("!L", ciphertext[-4:])[0]

wrpcap("step2.pcap", arp)

print ('Text: ' + data)
print ('icv:  ' + arp.icv.to_bytes(4, byteorder='big').hex())
print ('icv(num): ' + str(arp.icv))