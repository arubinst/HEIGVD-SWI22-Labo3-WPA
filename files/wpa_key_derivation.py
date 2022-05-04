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

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
from scapy.contrib.wpa_eapol import WPA_key
from scapy.layers.dot11 import *

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

#On effectue un filtre sur l'argument packets, on créé une list ne contenant que les packets correspondant à un 4WHS
list_Handshakes = []
for handshake in wpa:
    if handshake.haslayer(WPA_key):
        list_Handshakes.append(handshake)
print(len(list_Handshakes))

#On extrait les données des handshakes
list_HandshakesData = []
for handshake in list_Handshakes:
    list_HandshakesData.append(handshake.getlayer(WPA_key))

ANonce = list_HandshakesData[0].nonce
SNonce = list_HandshakesData[1].nonce
mic = list_HandshakesData[3].wpa_key_mic

#On place la mic key à 0 afin de pouvoir extraire les données
list_HandshakesData[3].wpa_key_mic=0

#On extrait les données grâce à underlayer de scapy.Packet
data = bytes(list_HandshakesData[3].underlayer)

#On effectue un filtre sur l'argument packets, on créé une liste ne contenant que les packets correspondant à un requête d'association
list_AssoReq = []
for packet in wpa:
    if packet.haslayer(Dot11AssoReq):
        list_AssoReq.append(packet)

#On sélectionne le premier élément de la liste, et on en extrait les données requises
assoReq = list_AssoReq[0]
ssid= assoReq.info.decode('ascii')
APmac = a2b_hex((assoReq.addr1).replace(":",""))
Clientmac = a2b_hex((assoReq.addr2).replace(":",""))

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
# Authenticator and Supplicant Nonces
# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary


B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

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
