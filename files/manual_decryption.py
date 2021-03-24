#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__ = "Abraham Rubinstein, Cassandre Wojciechowski, Gabriel Roch"
__copyright__ = "Copyright 2017, 2021, HEIG-VD"
__license__ = "GPL"
__version__ = "1.1"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from rc4 import RC4
import zlib

# Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('test.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# recuperation de icv dans le message (arp.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières de faire ceci...
icv_encrypted='{:x}'.format(arp.icv)

# text chiffré y-compris l'icv
message_encrypted=arp.wepdata+bytes.fromhex(icv_encrypted)


# déchiffrement rc4
cipher = RC4(seed, streaming=False)
cleartext = cipher.crypt(message_encrypted)

# le ICV est les derniers 4 octets - je le passe en format Long big endian
icv_enclair=cleartext[-4:]
icv_numerique=struct.unpack('!L', icv_enclair)

# Verification de l'ICV
if zlib.crc32(cleartext[:-4]).to_bytes(4, byteorder='little') == icv_enclair:
    print("ICV OK");
else:
    print("ICV PAS OK");

# le message sans le ICV
text_enclair=cleartext[:-4]

print('Text: ' + text_enclair.hex())
print('Text: ' , text_enclair)
print('icv:  ' + icv_enclair.hex())
print('icv(num): ' + str(icv_numerique))
print(icv_encrypted)

