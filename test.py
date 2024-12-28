#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

from sys import stdin
from lib.secp256k1 import secp

d = 5 # secret key
dG = secp.mult(d, secp.g) # public key

print(d, dG)

for k in range(1, 5):
    z = k + 100
    r,s  = secp.sign(z, d, k)
    print(r, s, z)
