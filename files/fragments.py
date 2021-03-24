#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from scapy.all import *
import binascii
from rc4 import RC4
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'


m = [b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x10\xc0\xa8\x01\xc8",
    b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x33\xc0\xa8\x01\xc8",
    b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x05\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x10\xc0\xa8\x01\xc8",
    b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8\x01d\x00\x00\x00\x00\x00\x10\x30\xa8\x01\xc8"]

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]
#La seed correspond à l'iv concaténé avec la clé
seed = arp.iv+key
#Instantiation de la classe RC4
cipher = RC4(seed, streaming=False)

FILE_NAME = "fragments.pcap"

if os.path.exists(FILE_NAME):
    print("File " + FILE_NAME + "already exists -> overwritting it")
    os.remove(FILE_NAME)
else:
    print("The file does not exist")

#Obligé de faire une copie sinon on modifie le contenu directement
init_SC = arp.copy().SC
i = 0
for m_it in m:

    #utilisation d'une copie
    trame_copy = arp.copy()
    #On incrémente le compteur du nombre de message déjà passés
    trame_copy.SC = init_SC + i
    
    #Tant qu'on a pas atteint le dernier message, on dit qu'il y en a d'autres à venir
    if i < len(m) - 1:
        trame_copy.FCfield.MF = True

    #On utilise la lib binascii qui implémente crc32 pour le "checksum" 
    icv = (binascii.crc32(m_it)).to_bytes(4, sys.byteorder)
    #On utilise la méthode crypt qui est la même pour chiffrer ou déchiffrer
    trame_copy.wepdata = cipher.crypt(m_it + icv)

    wrpcap(FILE_NAME, trame_copy, append = True)
    i += 1

print(FILE_NAME + " created!")