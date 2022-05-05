#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Obtention des paramètres pour la dérivation des clés WPA

Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Delphine Scherler et Wenes Limem"
__copyright__   = "Copyright 2022, HEIG-VD"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
from scapy.layers.dot11 import Dot11Beacon, Dot11


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

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap")

# Récupération d'un beacon frame
beacon_frame = wpa[0]
stats = beacon_frame[Dot11Beacon].network_stats()
# Récupération de l'adresse MAC de l'AP dans ce beacon
ap_mac = beacon_frame[Dot11].addr2.replace(':','')

# Récupération d'une trame d'authentification
auth_frame = wpa[1]
# Récupération de l'adresse MAC du client
client_mac = auth_frame[Dot11].addr1.replace(':','')

# Première trame du 4-way handshake
key_1 = wpa[5]
# Deuxième trame du 4-way handshake
key_2 = wpa[6]
# Récupération du nonce de l'Authenticator
anonce = key_1.load[13:45].hex()
# Récupération du nonce du Supplicant
snonce = raw(key_2)[65:-72].hex()

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = stats.get("ssid")
APmac       = a2b_hex(ap_mac)
Clientmac   = a2b_hex(client_mac)
# Authenticator and Supplicant Nonces
ANonce      = a2b_hex(anonce)
SNonce      = a2b_hex(snonce)

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")
