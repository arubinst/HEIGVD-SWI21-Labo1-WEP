#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypts a wep message with the given WEP key and fragments to multiple packets"""

__author__      = "Diego Villagrasa"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "diego.villagrasa@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from scapy.layers.dot11 import RadioTap
import binascii
from rc4 import RC4

# Sépare une liste l en n parties
def splitArray(l, n):
    m = len(l) // n
    a = list()
    for i in range(0, len(l), m):
        a.append(l[i:i+m])
    return a

# Ecrit le payload dans un packet scapy
def writeData(packet, key, data, last):
    # rc4 seed est composé de IV+clé
    seed = packet.iv+key

    # Calcul du icv avec un crc32 sur le payload
    icv_number = binascii.crc32(data)
    # transformation en bytes
    icv_enclair = icv_number.to_bytes(4, byteorder='little')

    # Combine le payload et l'icv
    frame = data + icv_enclair

    # Applique RC4 sur la frame
    cipher = RC4(seed, streaming=False)
    ciphertext = cipher.crypt(frame)

    # Remplace le payload, icv et incremente le SC
    packet.wepdata = ciphertext[:-4]
    packet.icv = int.from_bytes(ciphertext[-4:], "big")  
    packet.SC += 1

    # Reset la taille du header RadioTap
    packet[RadioTap].len = None

    # Set le flag fragmenté ainsi que si il reste des paquets
    if last:
        packet.FCfield = int.from_bytes(b'\x08\x41', "big")
    else:
        packet.FCfield = int.from_bytes(b'\x08\x45', "big")


#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

payload = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam luctus turpis ut nibh aliquam"

# Sépare lepayload en 3
payloads = splitArray(payload, 3)

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# Crée des paquets pour chque payload
for i in range(len(payloads)):
    writeData(arp, key, payloads[i], i==(len(payloads)-1))
    wrpcap("./outPcap/frag.cap", arp, append=True)
