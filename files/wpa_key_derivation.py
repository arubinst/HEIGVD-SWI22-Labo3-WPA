#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
from scapy.layers.eap import EAPOL

from files.pbkdf2 import pbkdf2


__author__ = "Abraham Rubinstein, Yann Lederrey, Sauge Ryan et Le Ray Quentin"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib

def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("wpa_handshake.cap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase = "actuelle"
A = "Pairwise key expansion"  # this string is used in the pseudo-random function


####### Begin modification ########
# Goal : Get ssid, AP MAC, ANonce, SNonce, Client mic test and data #
ssid = ""
APmac = ""
Clientmac = ""
ANonce = ""
cpt4Handshake = 0
mic_to_test = ""
SNonce = ""
for pkt in wpa:
    # GET ssid and AP MAC with a beacon frame
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        if pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info
            print("SSID" , ssid)
            APmac = a2b_hex(pkt.addr2.replace(":", ""))
            print("APmAc", APmac)
    # GET Client Mac and verify AP MAC with an Authentication frame
    if pkt.type == 0 and pkt.subtype == 0xB and len(Clientmac) == 0:
        Clientmac = a2b_hex(pkt.addr1.replace(":", ""))
        print("MAC address client %s " % pkt.addr1)
        print("AP address %s " % pkt.addr3)

    # GET ANonce, SNonce, client mic and the mic to test in 4-Way Handshake
    if pkt.haslayer(EAPOL):
        print("Frame number : ", cpt4Handshake)
        # GET ANonce
        if cpt4Handshake == 0:
            ANonce = pkt[EAPOL].load[13:13 + 0x20]
        # GET SNonce and client mic
        if cpt4Handshake == 1:
            SNonce = pkt[EAPOL].load[13:13 + 0x20]
            client_mic = pkt[EAPOL].load[77:77 + 16]
        # GET MIC test
        if cpt4Handshake == 3:
            mic_to_test = pkt[EAPOL].load[77:77 + 16]
            data = bytes(pkt[EAPOL])
            # Effacement du mic dans la payload
            toReplace = a2b_hex("00000000000000000000000000000000")
            data = data.replace(mic_to_test, toReplace)
        cpt4Handshake = cpt4Handshake + 1

####### End modification #####
# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                              SNonce)  # used in pseudo-random function

print("\n\nValues used to derivate keys")
print("============================")
print("Passphrase: ", passPhrase, "\n")
print("SSID: ", str(ssid, "utf-8", "\n"))
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("AP Nonce: ", b2a_hex(ANonce), "\n")
print("Client Nonce: ", b2a_hex(SNonce), "\n")

# calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)

pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

# expand pmk to obtain PTK
ptk = customPRF512(pmk, str.encode(A), B)

# calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16], data, hashlib.sha1)

print("\nResults of the key expansion")
print("=============================")
print("PMK:\t\t", pmk.hex(), "\n")
print("PTK:\t\t", ptk.hex(), "\n")
print("KCK:\t\t", ptk[0:16].hex(), "\n")
print("KEK:\t\t", ptk[16:32].hex(), "\n")
print("TK:\t\t", ptk[32:48].hex(), "\n")
print("MICK:\t\t", ptk[48:64].hex(), "\n")
print("MIC:\t\t", mic.hexdigest(), "\n")