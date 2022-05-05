#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Function useful to analyse packets
"""

from scapy.all import *
from binascii import a2b_hex, b2a_hex

def first_beacon(capture):
    """
    Return the first beacon packet of the capture file
    """
    for packet in capture:
        if packet.haslayer(Dot11Beacon):
            return packet

def first_assoReq(capture):
    """
    Return the first assoReq packet of the capture file
    """
    for packet in capture:
        if packet.haslayer(Dot11AssoReq):
                return packet

def handshake_first_package(capture):
    """
    Return the first handshake packet of the capture file
    """
    packet_nb = 0
    for packet in capture:
        if packet.haslayer(EAPOL):
            return packet_nb
        packet_nb += 1

def handshake_first_pkg_with_ap(capture, ap_mac):
    """
    Return the first handshake packet of the capture file
    """
    for packet in capture:
        if packet.haslayer(EAPOL):
            src = a2b_hex(packet.addr2.replace(":", ""))
            if src == ap_mac:
                return packet

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
