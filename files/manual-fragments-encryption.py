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

# Message se basant sur celui donné avec quelques modifications divié en trois
clear_msg = [b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00",
            b"\x06\x04\x00\x01\x90'\xe4\xeaa\xf2\xc0\xa8",
            b"\x01d\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xff"]

fragments = []
numberOfFragments = 3
for x in range(numberOfFragments):
    # lecture de capture initiale
    packet = rdpcap('arp.cap')[0]

    # More fragment à 1 sauf pour le dernier fragments
    packet.FCfield.MF = x != numberOfFragments - 1

    # initialisation du compteur de fragment à la valeur du compteur
    packet.SC = x

    # on réinitialise la taille des données qui sera ensuite mise à jour à l'écriture
    packet[RadioTap].len = None

    # calcul de l'icv
    icv = binascii.crc32(clear_msg[x]).to_bytes(4, byteorder='little')

    # chiffrement des données
    cipher = RC4(packet.iv + key_to_encrypt, streaming=False)
    cipherList = cipher.crypt(clear_msg[x] + icv)

    # on change les données dans la trame de base
    packet.wepdata = cipherList[:-4]

    # on change aussi le crc32 dans la trame de base
    packet.icv = struct.unpack('!L', cipherList[-4:])[0]

    # on ajoute le fragment à la liste
    fragments.append(packet)

# on écrit la liste des fragments chiffrés dans fichier pcap
wrpcap("step3.pcap", fragments)
