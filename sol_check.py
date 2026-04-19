#!/usr/bin/env python

import hashlib

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

def get_nonces_d(xstr: str):
    xstr = re.sub(r' \|.*', '', xstr).strip('[ ]\r\n')
    nd = [ int(x) for x in xstr.split() ]

    return nd[:-1], nd[-1]    

def vectorize_nonces_d(nonces: list[int], d: int) -> str:
    return '[ ' + ' '.join(str(x) for x in nonces + [ d ]) + ' ]'          

def adapt_lr_nonce_bounds():
    min_index = min_diff = None
    adapt_r = None # which bound has to be adapted

    for x_nd in x_nds:
        nonces, d = x_nd

        curr_min_index = curr_min_diff = None
        curr_adapt_r = None # which bound has to be adapted

        for i, n in enumerate(nonces):
            diff = min(n - lx_n[i], rx_n[i] - n)
            if diff < 0: # this solution can be skipped it already violates the current bounds
                curr_min_index = None;
                break    
                
            if curr_min_index is None or diff < curr_min_diff:
                curr_min_index = i
                curr_min_diff = diff

                curr_adapt_r = (rx_n[i] - n) == diff

        if curr_min_index is not None:
            min_index = curr_min_index
            min_diff = curr_min_diff

            adapt_r = curr_adapt_r

    if min_index is not None:
        min_diff += 1

        if adapt_r:
            rx_n[min_index] -= min_diff
        else:
            lx_n[min_index] += min_diff

        adapt_lr_nonce_bounds()

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
        
    x_nds = []
    with open(filepath) as file:
        for line in file:
           
            # get the nonces, d tuple of the solution
            n, d = get_nonces_d(line) 
            
            #print(d, file=stderr)

            if d == 0:
                continue

            pks = Btc.privateIntKeyToPublicKeyAddresses(d)
            
            for key, val in pks.items():
                if val == utxo:
                    print(f'The private key {d = } matches the public key {val} ({key})')
                    exit(0)

            x_nds.append((n, d))
     
    print('No private key was found.')

    # Determine the opt file
    filename_wo_ending = re.sub(r'\.sol', '', os.path.basename(filepath))

    opt_filepath = os.path.dirname(filepath)
    if opt_filepath != '':
        opt_filepath += '/'
    opt_filepath += filename_wo_ending;
    
    opt_lines = []
    with open(opt_filepath + '.opt') as file:
        for line in file:
            opt_lines.append(line)    

    opt_lines_first = opt_lines[:-2]    
    opt_lines_last = opt_lines[-2:] # TODO: make sure that lx, rx are really there - comments may have been added to the end of the opt-file! 

    # Extract lx and rx and get the nonces, d tuple
    lx_n, lx_d = get_nonces_d(opt_lines_last[0])
    rx_n, rx_d = get_nonces_d(opt_lines_last[1])   

    adapt_lr_nonce_bounds() # this slightly modifies lx_n and rx_n, such that the nonces of each current solution violate the bounds

    opt_lines_last[0] = vectorize_nonces_d(lx_n, lx_d)
    opt_lines_last[1] = vectorize_nonces_d(rx_n, rx_d)

    opt_lines = ''.join(opt_lines_first) + '\n'.join(opt_lines_last)

    sha1 = hashlib.sha1()
    
    sha1.update(opt_lines_last[0].encode("utf-8")) 
    sha1.update(opt_lines_last[1].encode("utf-8")) 

    # Persist the updated opt-file
    f = open(opt_filepath + '.' + sha1.hexdigest() + '.opt', 'w')

    print(opt_lines, file=f) 
    f.close() 
