#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

from sys import stdin
from lib.secp256k1 import inverseMod, secp

def inv(s):
    return inverseMod(s, g)

rsz_tuples = []

for line in stdin:
    (r, s, z) = [ int(x) for x in line.split() ] 
    rsz_tuples.append([ r, s, z ])

g = secp.n
n = len(rsz_tuples)

print("[]\n[\n]\n") # target section

# equation section
print('[')

modulo = []
d = []
i = 0

for rsz in rsz_tuples:
    print('[', end = ' ')
    (r, s, z) = rsz

    s_inv = inv(s)

    for j in range(n + 1):
        if i == j:
            print(1, end = ' ')
        elif j == n:
            print((-s_inv * r) % g, end = ' ')
        else:
            print(0, end = ' ')
    
    modulo.append(g)
    d.append((s_inv * z) % g)

    print(']')
    i += 1

print("]\n[ ", end = '')
for v in d:
    print(v, end = ' ') 
print(']') 

print()

print("[\n]\n[]\n[]\n") # inequation section

print('[ ', end = '')
for j in range(n + 1):
    print(0, end = ' ')
print(']')    

print('[ ', end = '')
for j in range(n + 1):
    print(0, end = ' ')
print(']')    

upper = [ g-1 for j in range(0, n+1) ]

print('[', *upper, sep=' ', end=" ]\n")
print('[', *modulo, sep=' ', end=' ]')