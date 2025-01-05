#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

from sys import stdin
from lib.secp256k1 import secp

d = 5 # secret key
dG = secp.mult(d, secp.g) # public key

priv_pubkey = [ d, dG ]
print(f'{priv_pubkey = }')

opt_sol = []
for k in range(1, 5):
    z = k + 100
    (r, s), corrected  = secp.sign(z, d, k)

    if corrected:
        opt_sol.append(secp.n - k)
    else:
        opt_sol.append(k)

    print(r, s, z, corrected)

opt_sol.append(d)

print(f'{opt_sol = }')