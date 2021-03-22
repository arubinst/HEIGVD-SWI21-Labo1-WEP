#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Gaëtan Daubresse et Jérôme Arn"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

#Cle wep BB:BB:BB:BB:BB:BB
key_to_encrypt= b'\xbb\xbb\xbb\xbb\xbb'

# Message se basant sur celui donné avec quelques modifications
clear_msg = b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x00\xc0\xa9\x02\xff"
# calcul du crc du message en le mettant directement en forme
clear_icv = binascii.crc32(clear_msg).to_bytes(4, byteorder='little')

# lecture de la trame pour avoir un template
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
# chiffrement rc4 des données et du crc32
cipher = RC4(arp.iv+key_to_encrypt, streaming=False)
ciphertext=cipher.crypt(clear_msg + clear_icv)

# on change les données dans la trame de base
arp.wepdata = ciphertext[:-4]
# on change aussi le crc32 dans la trame de base
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

# on écrit la trame chiffrée dans fichier pcap
wrpcap("step2.cap", arp)

# envoi de la trame
sendp(arp)
