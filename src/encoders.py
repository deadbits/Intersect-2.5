#!/usr/bin/python
# Intersect Framework (c) 2012
# Module for various encoders and crypto algo's
# that are used through-out the framework

import os, sys
from base64 import *
import struct


def b64_encode(data):
    encoded = b64encode(data)
    return encoded
    
def b64_decode(data):
    decoded = b64decode(data)
    return decoded
    
def babble_encode(data, safebase=0x30):
    encoded = ""
    for c in data:
        encoded += chr(((ord(c) & 0xf0) >> 4) | (safebase & 0xf0))
        encoded += chr((ord(c) & 0x0f) | (safebase & 0xf0))
    return encoded

def babble_decode(data):
    decoded = ""
    e_len = len(encoded)
    i = 0
    while i != e_len:
        decoded += chr(((ord(encoded[i]) & 0x0f) << 4) | (ord(encoded[i+1]) & 0x0f))
        i += 2
    return decoded