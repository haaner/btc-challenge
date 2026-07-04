#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

import argparse
#from sys import argv, stdin, exit
from lib.secp256k1 import secp
from os.path import basename, dirname
import re 

PRIV_KEY='private-key'

def check_privkey_value(value):
    if (ival := int(value)) <= 0 or str(ival) != value:
        exit(f'The private key must be integer and > 0.')
    return ival

def get_arg(args: list, key: str):
    return getattr(args, key.replace('-', '_'))  

def parse_args():
    parser = argparse.ArgumentParser(prog=basename(__file__),
        description='Generate sol-data from rsz-data and an integer private key', exit_on_error=True) 

    parser.add_argument('rsz_file') 

    parser.add_argument('--' + PRIV_KEY, default=None, type=check_privkey_value, help='The integer private key.', required=True) 
    args = parser.parse_args()

    privkey = get_arg(args, PRIV_KEY)
    
    return (args.rsz_file, privkey)

###############################################################################

rsz_file, privkey = parse_args()

# read the rsz tuple file
rsz_tuples = []

for line in open(rsz_file):
    (r, s, z) = [ int(x) for x in line.split() ] 

    rsz_tuples.append([ r, s, z ])

# compute the nonces for the private key

sol = []
for rsz in rsz_tuples:
    r, s, z = rsz

    s_inv = secp.inv(s)

    si_z = s_inv * z
    si_r_d = s_inv * r * privkey

    nonce = (si_z + si_r_d) % secp.n

    sol.append(nonce)
   
sol.append(privkey)

# write the sol file
filename = re.sub(r'\..*', '', basename(rsz_file))

directory = dirname(rsz_file)

if directory != '':
    directory += '/'

filename = directory + filename + '.sol'  

f = open(filename, 'w')
print('[', *sol, sep=' ', end=" ]\n", file=f)
f.close()

print (f'{filename} has been written.')