#!/usr/bin/env python

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

from lib.trx import PubKeySigMsg, Trx 
from lib.btc import Btc

import urllib.request
import json      

class Rsz:

    def _fetchTrxObject(self, offset):
        url = 'https://blockchain.info/address/' + self.utxo + '?format=json&offset=' + str(offset)        
        result = urllib.request.urlopen(url).read()
        return json.loads(result)
    
    def __init__(self, utxo: str):
        self.utxo = utxo

        if (self.utxo.startswith('bc1')):
            self.utxoHash = Btc.bechToHash160(utxo)
        else:
            self.utxoHash = Btc.wifToHash160(utxo)

        count = 100

        offset = 0
        obj = self._fetchTrxObject(offset)
        current_n = len(obj['txs'])
        
        total_n = obj['n_tx']
        
        self.satoshis = obj['final_balance']
        self.bitcoins = self.satoshis / 100000000;

        self.otrxs: list[Trx] = []

        pages = total_n // count

        if pages * count < total_n:
            pages += 1

        for k in range(pages):
            for i in range(current_n):
                txn = obj['txs'][i]

                inputs = txn['inputs']  
                n_inputs = len(inputs)  

                for ii in range(n_inputs):
                    addr = inputs[ii]['prev_out']['addr']
                    if addr == self.utxo:
                        self.otrxs.append(Trx(txn['hash']))
                        break  
            
            offset += count
            obj = self._fetchTrxObject(offset)
            current_n = len(obj['txs'])
    
    def tuples(self) -> list[PubKeySigMsg]:
        pk_count = 0;
        tp_count = 0;

        prsz_list = []
        for trx in self.otrxs:
            current_list = trx.getPubKeySigMsgList(self.utxoHash)
            pk_count += len(trx._pkMsgs)
            tp_count += len(trx._tprs)
            prsz_list = prsz_list + current_list

        return prsz_list

    def verifyTuples(self) -> bool:
        prsz_list = self.tuples()

        for prsz in prsz_list:
            if not prsz.verify():
                return False
                
        return True

    def __str__(self):
        return f'{{ {self.utxo=}, {self.utxoHash=} {self.bitcoins=}, {self.otrxs=} }}'
    
    def __repr__(self):
        return str(self)
    
if __name__ == '__main__':

    import sys

    if len(sys.argv) > 1:
        wif = sys.argv[1]
    else:
        wif = '18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8'

    prsz = Rsz(wif)
    if prsz.verifyTuples():
        for tuple in prsz.tuples():
            print(tuple.rs[0], tuple.rs[1], tuple.z)
    else:
        raise Exception('Prsz error') 
   