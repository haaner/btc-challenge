#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

if __name__ == '__main__':
    
    from sys import argv, stdin
    from lib.btc import Btc
    
    import re 

    if len(argv) > 1:
        utxo = argv[1]
    else:
        print(f'Usage: {argv[0]} 17Vu7st1U1KwymUKU4jJheHHGRVNqrcfLD < data/secp.sol')
        exit(1)

    print(f'Searching a private key for {utxo = }:')

    for line in stdin:
        l = re.sub(r' \|.*', '', line).strip('[ ]\r\n')
        rd = [ int(x) for x in l.split() ] 
        d = rd[-1]

        #print(d)

        pks = Btc.privateIntKeyToPublicKeyAddresses(d)
        
        for key, val in pks.items():
            if val == utxo:
                print(f'The private key {d = } matches the public key {val} ({key})')
                break  