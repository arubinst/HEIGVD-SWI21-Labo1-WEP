#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message with the given WEP key"""

__author__      = "Diego Villagrasa"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "diego.villagrasa@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

# Ecrit le payload dans un packet scapy
def writeData(packet, key, data):
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

    # Reset la taille du header RadioTap
    packet[RadioTap].len = None


# Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

payload = b"hello world"

#l ecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# Modifie le paquet
writeData(arp, key, payload)

# Ecrit le fichier Pcap
wrpcap("./outPcap/wep.cap", arp, append=False)
