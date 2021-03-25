#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually fragment a wep message into 3 fragments given the WEP key"""

__author__      = "Schranz Guillaume & Lièvre Loïc"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "guillaume.schranz@heig-vd.ch, loic.lievre@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key = b'\xaa\xaa\xaa\xaa\xaa'

#on assigne des valeurx hexa au texte
text = "aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8"

#on choisis un iv a 0 comme proposé dans le slide 25 du PDF wep
iv = bytes.fromhex("000000")

#seed avec l'iv et la clé définie
seed = iv+key

# chiffrement rc4
cipher = RC4(seed, streaming=False)

#on définit le nombre de fragments à 3
countFrag = 3

#on calcule le nombre de caractères par fragments
charsPerFrag = int(len(text) / countFrag)

#copie le texte dans une variable intermediaire qui 
#sera coupee à chaque itération
currentText = text

for i in range(0, countFrag):
    #reprend la trame du fichier pour la modifier
    #une trame de 'template' est reprise du fichier
    #à chaque fois car nous l'altérons avant de l'
    #écrire dans un fichier et cela est plus simple
    #à dépanner en cas de problème si on repart
    #toujours du même modèle
    arp = rdpcap('arp.cap')[0]

    #prend le message sous forme de bytes
    fragMessage = bytes.fromhex(currentText[:charsPerFrag])

    #enleve les n premiers caracteres deja framgentes
    currentText = currentText[charsPerFrag:]

    #calcul de l'icv avec le crc32
    icv = binascii.crc32(fragMessage).to_bytes(4, byteorder='little')

    #encrypte le message
    encryptedText = cipher.crypt(fragMessage + icv)

    #on complete la trame avec les wepdata et l'icv calculé
    arp.wepdata = encryptedText[:-4]
    clearICV = encryptedText[-4:]
    arp.iv = iv
    
    #reset longueur header sinon trame non reconnue correctement
    arp[RadioTap].len = None 

    #frame prend le numero du compteur
    arp.SC = i 

    #MF si pas dernière trame
    if i < countFrag-1:
        arp.FCfield |= 0b100 #code pour MF
    
    #on indique l'icv de la trame
    arp.icv = struct.unpack('!L', clearICV)[0]

    #insere les trames dans le fichier
    wrpcap("step3.pcap", arp, append = i > 0)