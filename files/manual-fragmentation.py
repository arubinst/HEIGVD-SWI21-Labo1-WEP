#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key and fragment the packet"""

__author__      = "Michaël da Silva, Nenad Rajic"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "michael.dasilva@heig-vd.ch, nenad.rajic@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

# Fonction de chiffrement des données
def encryption(data, key, arp):
    # Calcul du ICV + passage en bytes au format little endian
    icv_numerique = binascii.crc32(data.encode()) & 0xffffffff
    icv_enclair = icv_numerique.to_bytes(4, byteorder='little')
    # rc4 seed est composé de IV+clé
    seed = arp.iv + key
    # chiffrement rc4
    cipher = RC4(seed, streaming=False)
    ciphertext = cipher.crypt(data.encode() + icv_enclair)

    return ciphertext

# Fonction de création de frame à partir de fragment du message
def createFrame(data, key, arp):
    frame = arp
    # ICV du corps de la trame chiffré au format Big endian
    frame.icv = struct.unpack("!L", data[-4:])[0]
    # Corps de la trame chiffré sans l'ICV
    frame.wepdata = data[:-4]

    return frame

# Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'
# Message à utiliser dans notre paquet forgé (min. 36 caractères)
data = "HEIG-VD 2021, SWI: laboratoire 2 WEP"
# Nom du fichier contenant les paquets
fileName = "step3.pcap"
# Division du message en N string (pour N paquets)
numberFrags = 3
sizeData = len(data)//numberFrags
dataChunks = [data[i:i+sizeData] for i in range(0, len(data), sizeData)]
packets = []

for i in range(numberFrags):
    # lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
    arp = rdpcap('arp.cap')[0]
    # Fragment du message du paquet
    text = dataChunks[i]
    # Bit de "more fragment" à 1 sauf le dernier
    if i != numberFrags-1:
        arp.FCfield |= 0x4
    # Numéro du packet
    arp.SC = i
    # Reset de taille de packet 
    arp[RadioTap].len = None
    # Création du paquet
    cipherText = encryption(text, key, arp)
    frame = createFrame(cipherText, key, arp)
    packets.append(frame)

wrpcap(fileName, packets)