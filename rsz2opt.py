#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

import argparse
from sys import argv, stdin
from lib.secp256k1 import inverseMod, secp
from os.path import basename, dirname
import re 

def check_nb_value(value):
    if (ival := int(value)) > 255:  
        raise argparse.ArgumentTypeError(f'The value {value} must be smaller than 256.')
    if ival < 1:
        raise argparse.ArgumentTypeError(f'The value {value} must be greater than 0.')

    return ival

def check_nbm_value(value):
    ival = check_nb_value(value)
    if ival > 252:
        print(f'Using {NBM} values > 252 will probably not work!')
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

    parser.add_argument('rszfile') 
    parser.add_argument('--' + NBM, type=check_nbm_value) 
    parser.add_argument('--nonce-bits-equal', type=check_nb_value) 
    parser.add_argument('--' + SKIP, default=0, type=check_skip_value) 

    args = parser.parse_args()

    nbe = args.nonce_bits_equal
    nbm = args.nonce_bits_max

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

    return (args.rszfile, nbm, nonce_max, nbe, nonce_diff_max, args.skip)

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

(rsz_file, nonce_bits_max, nonce_max, nonce_bits_equal, nonce_diff_max, rsz_skip) = parse_args()

rsz_tuples = []

for line in open(rsz_file):
    (r, s, z) = [ int(x) for x in line.split() ] 

    if rsz_skip > 0:
        rsz_skip -= 1
        continue

    rsz_tuples.append([ r, s, z ])

def get_needed_rsz_count():
    for nbm, n in nbm_n.items():
        if nonce_bits_max <= nbm:
            return n
        
    raise Exception(f'Something is flawed: {nonce_bits_max} > {nbm}')

def inv(s):
    return inverseMod(s, g)

rsz_n = len(rsz_tuples)
rsz_needed = get_needed_rsz_count()

if rsz_needed > rsz_n:
    raise Exception(f'You have too few rsz tuples {rsz_n} < {rsz_needed}! You have to choose lower values for "{NBM}" or "{SKIP}"')

rsz_n = rsz_needed

filename = re.sub(r'\..*', '', basename(rsz_file))

if nonce_bits_max != None:
    filename += '.nbm' + str(nonce_bits_max)
if nonce_bits_equal != None:
    filename += '.nbe' + str(nonce_bits_equal)
if rsz_skip:
    filename += '.skip' + str(rsz_skip)

directory = dirname(rsz_file)

if directory != '':
    directory += '/'

filename = directory + filename + '.opt'  

f = open(filename, 'w')

print("[]\n[\n]\n", file=f) # target section

# equation section
print('[', file=f)

modulo = []
d = []
i = 0

for rsz in rsz_tuples:
    print('[', end = ' ', file=f)
    (r, s, z) = rsz

    s_inv = inv(s)

    for j in range(rsz_n + 1):
        if i == j:
            print(1, end = ' ', file=f)
        elif j == rsz_n:
            print((-s_inv * r) % g, end = ' ', file=f)
        else:
            print(0, end = ' ', file=f)
    
    modulo.append(g)
    d.append((s_inv * z) % g)

    print(']', file=f)
    i += 1

    if i == rsz_n:
        break

print("]\n[ ", end = '', file=f)
for v in d:
    print(v, end = ' ', file=f) 
print(']', file=f) 
print('[', *modulo, sep=' ', end=" ]\n", file=f) # solution: modulo section

print(file=f)

# inequation section
if nonce_diff_max == None:
    print("[\n]\n[]\n[]\n", file=f) 
else:
    rows = 0
    print('[', file=f)
    for i in range(rsz_n):
        for j in range(i+1, rsz_n):
            row = []
            for k in range(i):    
                row.append(0)

            row.append(1)
            row = row + [ 0 for k in range(j-i-1) ]           
            row.append(-1)
            row = row + [ 0 for k in range(j + 1, rsz_n+1) ]           

            print('[', *row, sep=' ', end=" ]\n", file=f)
            rows += 1
    print(']', file=f)

    lower = [ -nonce_diff_max for j in range(0, rows) ]
    upper = [ nonce_diff_max for j in range(0, rows) ]
    
    print('[', *lower, sep=' ', end=" ]\n", file=f)
    print('[', *upper, sep=' ', end=" ]\n\n", file=f)
        
# solution: digit section
print('[ ', end = '', file=f)
for j in range(rsz_n + 1):
    print(0, end = ' ', file=f)
print(']', file=f)    

# solution: lower bound section
print('[ ', end = '', file=f)
for j in range(rsz_n + 1):
    print(1, end = ' ', file=f)
print(']', file=f)    

# solution: upper bound section
upper = [ nonce_max for j in range(0, rsz_n) ] # the max values for the nonces
upper.append(g-1) # the max value for the private key

print('[', *upper, sep=' ', end=" ]\n", file=f)

f.close()

print (f'{filename} has been written.')