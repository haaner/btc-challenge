#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

import argparse
from sys import argv, stdin
from lib.secp256k1 import inverseMod, secp
from os.path import basename

def check_nb_value(value):
    if (ival := int(value)) > 255:  
        raise argparse.ArgumentTypeError(f'The value {value} must be smaller than 256.')
    if ival < 1:
        raise argparse.ArgumentTypeError(f'The value {value} must be greater than 0.')

    return ival

def check_nbm_value(value):
    ival = check_nb_value(value)
    # if ival > 252 print a warning that biases using (256 - ival) bits will probably not work
    return ival

def check_skip_value(value):
    if (ival := int(value)) < 0:
        raise argparse.ArgumentTypeError(f'The value {value} must be >= 0.')

g = secp.n
p = secp.p

NBM='nonce-bits-max'
SKIP='skip'

def parse_args():
    parser = argparse.ArgumentParser(prog=basename(__file__),
        description='Generate opt-data from rsz-data',
        epilog='0ptX may solve your problem(s) - www.0ptX.de', exit_on_error=True) 

    parser.add_argument('--' + NBM, type=check_nbm_value) 
    parser.add_argument('--nonce-bits-equal', type=check_nb_value) 
    parser.add_argument('--' + SKIP, type=check_skip_value) 

    args = parser.parse_args()

    nbe = args.nonce_bits_equal
    nbm = args.nonce_bits_max
    rsz_skip = args.skip

    if nbe == None:
        nonce_diff_max = None 
        if nbm == None:
            nbm = 252     
    else:   
        nonce_diff_max = pow(2, 256) - 1
        for i in range(nbe):
            nonce_diff_max -= pow(2, 255-i)
        if nonce_diff_max < 0:
            nonce_diff_max = 0

    if nbm == None:
        nonce_max = g - 1
    else:
        nonce_max = pow(2, nbm) - 1

    if rsz_skip == None:
        rsz_skip = 0

    return (nbm, nonce_max, nonce_diff_max, rsz_skip)

nbm_n = { # see https://eprint.iacr.org/2019/023.pdf (Biased Nonce Sense)
    128: 2,
    170: 3,
    190: 4,
    200: 5,
    208: 6,
    212: 7,
    220: 8,
    224: 9,
    227: 10,
    228: 11,
    230: 12,
    232: 13,
    234: 14,
    236: 15,
    238: 16,
    239: 17,
    240: 18,
    241: 19,
    242: 20,
    243: 22,
    244: 24,
    245: 28,
    246: 31,
    247: 35,
    248: 40,
    249: 50,
    250: 70,
    251: 100,
    252: 150,
    253: 200,
    254: 250,
    255: 300 
}

(nonce_bits_max, nonce_max, nonce_diff_max, rsz_skip) = parse_args()

def get_needed_rsz_count():
    for nbm, n in nbm_n.items():
        if nonce_bits_max <= nbm:
            return n
        
    raise Exception(f'Something is flawed: {nonce_bits_max} > {nbm}')

def inv(s):
    return inverseMod(s, g)

rsz_tuples = []

for line in stdin:
    (r, s, z) = [ int(x) for x in line.split() ] 

    if rsz_skip > 0:
        rsz_skip -= 1
        continue

    rsz_tuples.append([ r, s, z ])

rsz_n = len(rsz_tuples)
rsz_needed = get_needed_rsz_count()

if rsz_needed > rsz_n:
    raise Exception(f'You have too few rsz tuples {rsz_n} < {rsz_needed}! You have to choose lower values for "{NBM}" or "{SKIP}"')

rsz_n = rsz_needed

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

    for j in range(rsz_n + 1):
        if i == j:
            print(1, end = ' ')
        elif j == rsz_n:
            print((-s_inv * r) % g, end = ' ')
        else:
            print(0, end = ' ')
    
    modulo.append(g)
    d.append((s_inv * z) % g)

    print(']')
    i += 1

    if i == rsz_n:
        break

print("]\n[ ", end = '')
for v in d:
    print(v, end = ' ') 
print(']') 
print('[', *modulo, sep=' ', end=" ]\n") # solution: modulo section

print()

# inequation section
if nonce_diff_max == None:
    print("[\n]\n[]\n[]\n") 
else:
    rows = 0
    print('[')
    for i in range(rsz_n):
        for j in range(i+1, rsz_n):
            row = []
            for k in range(i):    
                row.append(0)

            row.append(1)
            row = row + [ 0 for k in range(j-i-1) ]           
            row.append(-1)
            row = row + [ 0 for k in range(j + 1, rsz_n+1) ]           

            print('[', *row, sep=' ', end=" ]\n")
            rows += 1
    print(']')

    lower = [ -nonce_diff_max for j in range(0, rows) ]
    upper = [ nonce_diff_max for j in range(0, rows) ]
    
    print('[', *lower, sep=' ', end=" ]\n")
    print('[', *upper, sep=' ', end=" ]\n\n")
        
# solution: digit section
print('[ ', end = '')
for j in range(rsz_n + 1):
    print(0, end = ' ')
print(']')    

# solution: lower bound section
print('[ ', end = '')
for j in range(rsz_n + 1):
    print(1, end = ' ')
print(']')    

# solution: upper bound section
upper = [ nonce_max for j in range(0, rsz_n) ] # the max values for the nonces
upper.append(g-1) # the max value for the private key

print('[', *upper, sep=' ', end=" ]\n")