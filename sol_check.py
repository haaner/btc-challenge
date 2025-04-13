#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

if __name__ == '__main__':
    
    from sys import argv, stdin, stderr
    from lib.btc import Btc
    
    import re 
    import os.path

    if len(argv) < 2:
        print(f'Usage: {argv[0]} data/17Vu7st1U1KwymUKU4jJheHHGRVNqrcfL.sol')
        exit(1)
    
    filepath = argv[1]

    utxo = re.sub(r'\..*', '', os.path.basename(filepath))
    
    print(f'Searching a private key for {utxo = }:')
    
    with open(filepath) as file:
        for line in file:
            l = re.sub(r' \|.*', '', line).strip('[ ]\r\n')
            rd = [ int(x) for x in l.split() ] 
            d = rd[-1]

            print(d, file=stderr)

            if d == 0:
                continue

            pks = Btc.privateIntKeyToPublicKeyAddresses(d)
            
            for key, val in pks.items():
                if val == utxo:
                    print(f'The private key {d = } matches the public key {val} ({key})')
                    exit(0)
