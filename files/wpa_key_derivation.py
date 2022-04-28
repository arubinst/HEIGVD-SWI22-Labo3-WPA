#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey. Modifié par David Pellissier et Michael Ruckstuhl"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac
import hashlib
from scapy.contrib.wpa_eapol import WPA_key


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


def get_association_info(packets):
    for p in packets:
        if p.haslayer("Dot11AssoReq"):
            ssid = p.info
            ap_mac = a2b_hex(p.addr1.replace(':', ''))
            client_mac = a2b_hex(p.addr2.replace(':', ''))
            return ssid, ap_mac, client_mac

    raise Exception("Couldn't find WPA association")


def get_hand_shake(packets):
    handshake = []
    for p in packets:
        if p.haslayer(WPA_key):
            handshake.append(p[WPA_key])

    if len(handshake) != 4:
        raise Exception("Couldn't find all 4 packets of the handshake")

    return handshake


def main():
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap("wpa_handshake.cap")

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    ssid, ap_mac, client_mac = get_association_info(wpa)
    pass_phrase = "actuelle"
    A = "Pairwise key expansion"  # this string is used in the pseudo-random function

    handshake = get_hand_shake(wpa)
    hs1 = handshake[0]
    hs2 = handshake[1]
    hs3 = handshake[2]
    hs4 = handshake[3]

    # Authenticator and Supplicant Nonces
    a_nonce = hs1.nonce
    s_nonce = hs2.nonce

    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    mic_to_test = hs4.wpa_key_mic

    hs4.wpa_key_mic = ""  # set MIC bytes to 0
    data = bytes(hs4.underlayer)

    B = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(a_nonce, s_nonce) + max(a_nonce,
                                                                                        s_nonce)  # used in pseudo-random function
    print("Values used to derivate keys")
    print("============================")
    print("Passphrase: ", pass_phrase, end="\n\n")
    print("SSID: ", ssid, "\n")
    print("AP Mac: ", b2a_hex(ap_mac), end="\n\n")
    print("CLient Mac: ", b2a_hex(client_mac), end="\n\n")
    print("AP Nonce: ", b2a_hex(a_nonce), end="\n\n")
    print("Client Nonce: ", b2a_hex(s_nonce), end="\n\n")
    print("Data: ", b2a_hex(data), end="\n\n")
    print("MIC to TEST: ", b2a_hex(mic_to_test))

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pass_phrase = str.encode(pass_phrase)

    pmk = pbkdf2(hashlib.sha1, pass_phrase, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)

    print("\nResults of the key expansion")
    print("=============================")
    print("PMK:\t\t", pmk.hex(), end="\n\n")
    print("PTK:\t\t", ptk.hex(), end="\n\n")
    print("KCK:\t\t", ptk[0:16].hex(), end="\n\n")
    print("KEK:\t\t", ptk[16:32].hex(), end="\n\n")
    print("TK:\t\t", ptk[32:48].hex(), end="\n\n")
    print("MICK:\t\t", ptk[48:64].hex(), end="\n\n")
    print("MIC:\t\t", mic.hexdigest())


if __name__ == "__main__":
    main()
