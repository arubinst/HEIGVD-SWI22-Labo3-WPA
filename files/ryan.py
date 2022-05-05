#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""
from pstats import Stats

from scapy.layers.dot11 import Dot11Elt, Dot11, Dot11Beacon, Dot11ProbeResp
from scapy.layers.eap import EAPOL

from files.pbkdf2 import pbkdf2
import numpy as np

__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
# from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
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
# ssid        = "SWI"
ssid = ""
# APmac       = a2b_hex("cebcc8fdcab7")
APmac = ""
# Clientmac   = a2b_hex("0013efd015bd")
Clientmac = ""
print(len(wpa))
ANonce = ""
cpt = 0
mic_to_test = ""
SNonce = ""
#getlayer(Raw).load)[202:234]
for pkt in wpa:
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        if pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info
            print("SSID" , ssid)
            APmac = bytes(pkt.addr2, "utf-8")
            print("APmAc", APmac)
    if pkt.type == 0 and pkt.subtype == 0xB and len(Clientmac) == 0:
        Clientmac = bytes(pkt.addr1, "utf-8")
        # ssid = pkt.info.decode()
        # APmac = a2b_hex(pkt.addr2)
        print("MAC address client %s " % pkt.addr1)
        print("AP address %s " % pkt.addr3)

    if pkt.haslayer(EAPOL):
        print("Frame number : ", cpt)
        print(pkt.summary())
        if cpt == 0:
            ANonce = pkt[EAPOL].load[13:13 + 0x20]
            print("ANonce", pkt[EAPOL].load[13:13 + 0x20].hex())
        if cpt == 1:
            SNonce = pkt[EAPOL].load[13:13 + 0x20]
            print("SNonce", pkt[EAPOL].load[13:13 + 0x20].hex())
            client_mic = pkt[EAPOL].load[77:77 + 16]
            print("Client mic", client_mic.hex())
        if cpt == 3:
            mic_to_test = pkt[EAPOL].load[77:77 + 16]
            print("MIC To test", mic_to_test)
        cpt = cpt + 1
# Authenticator and Supplicant Nonces
# ANonce = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
#SNonce = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
#mic_to_test = "36eef66540fa801ceee2fea9b7929b40"
B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                              SNonce)  # used in pseudo-random function

data = a2b_hex(
    "0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")  # cf "Quelques détails importants" dans la donnée

print("\n\nValues used to derivate keys")
print("============================")
print("Passphrase: ", passPhrase, "\n")
print("SSID: ", ssid, "\n")
# print("AP Mac: ", b2a_hex(APmac), "\n")
print("AP Mac: ", APmac, "\n")
# print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("CLient Mac: ", Clientmac, "\n")
print("AP Nonce: ", b2a_hex(ANonce), "\n")
print("Client Nonce: ", b2a_hex(SNonce), "\n")

# calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
# ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

# ap_list.append((pkt.ssid, pkt.addr2))
# print("Réseau SSID: %s et MAC address: %s " % (wpa.info, wpa.addr2))
# print(int(ord(wpa[Dot11Elt:3].info)))


# print (Stats)
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
