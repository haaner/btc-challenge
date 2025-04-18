#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

import argparse
from sys import argv, stdin
from lib.secp256k1 import inverseMod, secp

def inv(s):
    return inverseMod(s, g)

g = secp.n

def check_value(value):
    if (ival := int(value)) > 255:  
        raise argparse.ArgumentTypeError(f'Der Wert {value} muss kleiner 256 sein.')
    if ival < 1:
        raise argparse.ArgumentTypeError(f'Der Wert {value} muss größer 0 sein.')
    if pow(2, ival) > g:
        raise argparse.ArgumentTypeError(f'Der Wert 2^{value} muss kleiner oder gleich {g} sein.')

    return ival

def parse_args(g):
    parser = argparse.ArgumentParser() 

    parser.add_argument('--nonce-bits-max', type=check_value) 
    parser.add_argument('--nonce-bits-equal', type=check_value) 

    args = parser.parse_args()

    nbm = args.nonce_bits_max
    if nbm == None:
        nonce_max = g - 1
    else:
        nonce_max = pow(2, nbm) - 1

    nbe = args.nonce_bits_equal
    if nbe == None:
        nonce_diff_max = None
    else:
        nonce_diff_max = g - 1
        for i in range(nbe):
            nonce_diff_max -= pow(2, 255-i)
        if nonce_diff_max < 0:
            nonce_diff_max = 0
       
    return (nonce_max, nonce_diff_max)

rsz_tuples = []

for line in stdin:
    (r, s, z) = [ int(x) for x in line.split() ] 
    rsz_tuples.append([ r, s, z ])

(nonce_max, nonce_diff_max) = parse_args(g)

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

# inequation section
if nonce_diff_max == None:
    print("[\n]\n[]\n[]\n") 
else:
    rows = 0
    print('[')
    for i in range(n):
        for j in range(i+1, n):
            row = []
            for k in range(i):    
                row.append(0)

            row.append(1)
            row = row + [ 0 for k in range(j-i-1) ]           
            row.append(-1)
            row = row + [ 0 for k in range(j + 1, n+1) ]           

            print('[', *row, sep=' ', end=" ]\n")
            rows += 1
    print(']')

    lower = [ -nonce_diff_max for j in range(0, rows) ]
    upper = [ nonce_diff_max for j in range(0, rows) ]
    
    print('[', *lower, sep=' ', end=" ]\n")
    print('[', *upper, sep=' ', end=" ]\n\n")
        
# solution: digit section
print('[ ', end = '')
for j in range(n + 1):
    print(0, end = ' ')
print(']')    

# solution: lower bound section
print('[ ', end = '')
for j in range(n + 1):
    print(0, end = ' ')
print(']')    

# solution: upper bound section
upper = [ nonce_max for j in range(0, n) ] # the max values for the nonces
upper.append(g-1) # the max value for the private key

print('[', *upper, sep=' ', end=" ]\n")
print('[', *modulo, sep=' ', end=' ]') # solution: modulo section