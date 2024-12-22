#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

from sys import stdin
from lib.secp256k1 import randrange, secp

d = 2 # secret key
dG = secp.mult(d, secp.g) # public key

print(d, dG)