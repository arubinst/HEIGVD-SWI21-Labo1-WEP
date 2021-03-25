#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message with a WEP key with fragments"""

__author__      = "Robin Cuénoud, Florian Mülhauser"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
import binascii

from scapy.layers.l2 import ARP

from rc4 import RC4
#Cle wep FF:FF:FF:FF:FF
key= b'\xff\xff\xff\xff\xff'

# import pour avoir un modèle
arp = rdpcap('arp.cap')[0]



# frame copiée depuis wireshark
cleartext =  b"\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01" \
b"\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\xff\x00\x00\x00\x00\x00\x00" \
b"\xc0\xa8\x02\xff"

iv = b"\x0c\x4d\x5c"

# On a besoin de 3 fragements
nbFragments = 3

# On regarde la taille voulue des fragements (pour qu'ils soient égal)
length = int(len(cleartext)/nbFragments)

# On separe le clearText en 3
splittedText = (cleartext[:length], cleartext[length:2* length], cleartext[2* length:])

# rc4 seed est composé de IV+clé
seed = iv+key

# chiffrement RC4
cipher = RC4(seed, streaming=False)

for i in range(nbFragments):
    fragment = splittedText[i]

    clear_icv = binascii.crc32(fragment).to_bytes(4,byteorder='little')
    ciphertext = cipher.crypt(fragment + clear_icv)

    # on met a jour le numéro de fragment
    arp.SC = i

    # le ICV est les derniers 4 octets - je le passe en format Long big endian
    arp.wepdata = ciphertext[:-4]
    arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

    # On met a jour le bit qui indique s'il reste des fragment
    if(i == nbFragments - 1): arp.FCfield.MF = 0
    else: arp.FCfield.MF = 1

    # On doit réinitialiser la taille du paquet pour que ça se mette a jour correctement en fonction de notre séparation
    arp[RadioTap].len = None

    wrpcap("created_fragment_arp.cap", arp, append = True)


#sendp(arp)
