#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually send a fragmented wep message given the WEP key"""

__author__ = "Arthur Bécaud, Bruno Egremy"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "arthur.becaud@heig-vd.ch, bruno.egremy@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from rc4 import RC4
import binascii

# message from capture template 'arp.cap', key and a random iv
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64' \
          b'\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
key = b'\xaa\xaa\xaa\xaa\xaa'
iv = b'\x01\x23\x45'

# set the number of fragments to generate
# /!\ there is no verification about the number set
nb_frag = 3
print("msg text: " + str(message))
# init rc4 with a seed (iv+key)
cipher = RC4(iv + key, streaming=False)

# read template wireshark capture
arp = rdpcap('arp.cap')[0]
# update arp iv and radiotap
arp.iv = iv
arp[RadioTap].len = None

for num_frag in range(nb_frag):
    # fragment message
    msg_frag = message[(len(message) // nb_frag) * num_frag:
                       (len(message) // nb_frag) * (num_frag + 1) if num_frag + 1 < nb_frag else None]
    print("frag txt: " + str(msg_frag))
    # compute icv
    icv = binascii.crc32(msg_frag).to_bytes(4, byteorder='little')
    # encrypt msg_frag+icv
    ciphertext = cipher.crypt(msg_frag + icv)
    # update arp sc, more fragment flag, wepdata and icv
    arp.SC = num_frag
    arp.FCfield.MF = num_frag + 1 < nb_frag
    arp.wepdata = ciphertext[:-4]
    arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
    # write fragment in wireshark capture
    wrpcap('arp-fragments.cap', arp, append=num_frag != 0)
