if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

from aux import parseVarint

class Signature:
    def __init__(self, raw):
        self.raw = raw

        compound_identifier = raw[:2]
        if compound_identifier != '30':
            raise Exception('unknown compound identifier')
        raw = raw[2:] 

        total_len, raw = parseVarint(raw)

        if raw[:2] != '02':
            raise Exception('unknown first type specifier')
        raw = raw[2:] 

        first_len_bytes, raw = parseVarint(raw)
        first_len_hex_chars = 2 * first_len_bytes
        
        self.r = raw[:first_len_hex_chars]
        raw = raw[first_len_hex_chars:] # remove r

        if raw[:2] != '02':
            raise Exception('unknown second type specifier')
        raw = raw[2:] 

        sec_len_bytes, raw = parseVarint(raw)
        sec_len_hex_chars = 2 * sec_len_bytes

        self.s = raw[:sec_len_hex_chars]
        raw = raw[sec_len_hex_chars:] # remove s
        
        if total_len - first_len_bytes - sec_len_bytes - 4 != 0:
            raise Exception('signature length mismatch')

        if raw not in [ '01', '02', '03' ]:
            raise Exception('unknown hashing sequence') # ANYONECANPAY signature handling is not implemented

        self.hashingSequence = int('0x' + raw, 16).to_bytes(4, byteorder='little').hex()

    def __str__(self):
        return f'{{ {self.raw=}, {self.r=}, {self.s=}, {self.hashingSequence=} }}'
    
    def __repr__(self):
        return str(self)        

class Operation:
    EQUAL = '87'
    HASH160 = 'a9'
    PUSHBYTES_20 = '14'
    PUSHBYTES_32 = '20'
    PUSHBYTES_33 = '21'
    PUSHBYTES_65 = '41'
    PUSHBYTES_71 = '47'
    PUSHBYTES_72 = '48'
    PUSHBYTES_73 = '49'
    CHECKSIG = 'ac'
    DUP = '76'
    EQUALVERIFY = '88'
    ZERO = '00'
    ONE = '51'

    @staticmethod
    def parseCode(raw: str):
        op_code = raw[:2]
        raw = raw[2:]

        return op_code, raw

class ScriptType:
    P2PK = 'P2PK'
    P2PKH = 'P2PKH'
    P2SH = 'P2SH'
    P2WPKH = 'P2WPKH'
    P2WSH = 'P2WSH'
    P2TR = 'P2TR'
    
class ScriptSig:
    def __init__(self, raw, start_index):
        self.raw = raw
        self.startIndex = start_index

        script_sig_bytes, raw = parseVarint(raw)
        script_sig_len = script_sig_bytes * 2

        script_sig = raw[:script_sig_len] 

        raw = raw[script_sig_len:] 
        self.raw = self.raw[:len(self.raw) - len(raw)]

        self.endIndex = self.startIndex + len(self.raw)

        #print(f"{script_sig=}")

        op_code, script_sig = Operation.parseCode(script_sig)

        if op_code == Operation.ZERO: 
            self.type = ScriptType.P2SH

            op_code, script_sig = Operation.parseCode(script_sig)
            if op_code != Operation.PUSHBYTES_71:
                raise Exception('unknown unlocking script')
            
            self.signature = Signature(script_sig[:142])
            script_sig = script_sig[142:]
            
            op_code, script_sig = Operation.parseCode(script_sig)
            if op_code != Operation.PUSHBYTES_71:
                raise Exception('unknown unlocking script')

            self.pubKey = None # TODO p2sh: Pay-to-script-hash. The public key(s) are packed into the redeem script which is the last item in scriptSig. To get them you need to parse the redeem script (which itself is a script) and look for key patterns (push of 33 bytes).

            script_sig = script_sig[142:]
            if script_sig != '':
                raise Exception('unknown unlocking script')
                            
        elif op_code in [ Operation.PUSHBYTES_71, Operation.PUSHBYTES_72, Operation.PUSHBYTES_73 ]:

            byte_count = int('0x' + op_code, 16);
            char_count = byte_count * 2

            self.signature = Signature(script_sig[:char_count])
            script_sig = script_sig[char_count:]

            if op_code == Operation.PUSHBYTES_71 and script_sig == '':
                self.type = ScriptType.P2PK 
                self.pubKey = None
            else:
                self.type = ScriptType.P2PKH

                op_code, script_sig = Operation.parseCode(script_sig)
                if op_code in [ Operation.PUSHBYTES_33, Operation.PUSHBYTES_65 ]:

                    byte_count = int('0x' + op_code, 16);
                    char_count = byte_count * 2

                    self.pubKey = script_sig[:char_count]

                    script_sig = script_sig[char_count:]
                    if script_sig != '':
                        raise Exception('unknown unlocking script')
                else:
                    raise Exception('unknown unlocking script')
            
        else:
            raise Exception('unknown unlocking script') # TODO Nested Segwit / Native Segwit

    def __str__(self):
        return f'{{ {self.raw=}, {self.startIndex=}, {self.endIndex=}, {self.type=}, {self.signature=}, {self.pubKey=} }}'
    
    def __repr__(self):
        return str(self)

class Input:
    def __init__(self, raw, offset):
        self.raw = raw

        (self.prevTrxId, self.prevTrxVout), raw = self._extractPreviousTrxIdVout(raw)

        #spk = self._extractScriptPubKey(*trx_prev_id_vout)
        offset2 = len(self.raw) - len(raw)
        self.sigScript = ScriptSig(raw, offset + offset2)

        self.raw = self.raw[:offset2 + len(self.sigScript.raw) + 8]

        # check the locktime end sequence
        end_sequence = self.raw[-8:]
        if end_sequence != 'ffffffff':
            raise Exception('unknown input locktime end sequence')       

    @staticmethod
    def _extractPreviousTrxIdVout(trx: str):

        # extract prev trx id and reverse its byte order
        prev_trx_id = trx[:64]
        trx = trx[64:]
        prev_trx_id_rev = int('0x' + prev_trx_id, 16).to_bytes(32, byteorder='little').hex()
        
        # extract prev trx vout and reverse its byte order
        prev_trx_vout = trx[:8]
        trx = trx[8:] 
        prev_trx_vout_rev = int('0x' + prev_trx_vout, 16).to_bytes(4, byteorder='little').hex()
    
        prev_trx_vout_rev_int = int('0x' + prev_trx_vout_rev, 16) # convert vout to integer

        return ((prev_trx_id_rev, prev_trx_vout_rev_int), trx)    
    
    def __str__(self):
        return f'{{ {self.raw=}, {self.prevTrxId=}, {self.prevTrxVout=}, {self.sigScript=} }}'
    
    def __repr__(self):
        return str(self)

class ScriptPubKey:
    def __init__(self, raw):
        self.raw  = raw

        op_code, raw = Operation.parseCode(raw)

        if op_code == Operation.HASH160:
            self.type = ScriptType.P2SH
            
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.PUSHBYTES_20:
                raise Exception('unknown locking script')
            
            self.pubKey = raw[:40]
            raw = raw[40:]
        
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.EQUAL:
                raise Exception('unknown locking script end sequence')
            
        elif op_code in [ Operation.PUSHBYTES_33, Operation.PUSHBYTES_65 ]: 
            self.type = ScriptType.P2PK

            byte_count = int('0x' + op_code, 16);
            char_count = byte_count * 2
            
            self.pubKey = raw[:char_count]
            raw = raw[char_count:]
        
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.CHECKSIG:
                raise Exception('unknown locking script end sequence')
            
        elif op_code == Operation.DUP: 
            self.type = ScriptType.P2PKH

            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.HASH160:
                raise Exception('unknown locking script')
            
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.PUSHBYTES_20:
                raise Exception('unknown locking script')
            
            self.pubKey = raw[:40]
            raw = raw[40:]
        
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.EQUALVERIFY:
                raise Exception('unknown locking script end sequence')
            
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.CHECKSIG:
                raise Exception('unknown locking script end sequence')

        elif op_code == Operation.ZERO:             
            op_code, raw = Operation.parseCode(raw)

            if op_code == Operation.PUSHBYTES_20:
                self.type = ScriptType.P2WPKH
                
                self.pubKey = raw[:40]
                raw = raw[40:]

            elif op_code == Operation.PUSHBYTES_32:
                self.type = ScriptType.P2WSH
                
                self.pubKey = raw[:64]
                raw = raw[64:]

            else:
                raise Exception('unknown locking script')

        elif op_code == Operation.ONE:             
            self.type = ScriptType.P2TR

            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.PUSHBYTES_32:
                raise Exception('unknown locking script')                     
            
            self.pubKey = raw[:64]
            raw = raw[64:]            
            
        else:
            raise Exception('unknown locking script')     

        self.raw = self.raw[:len(self.raw) - len(raw)]           
        
    def __str__(self):
        return f'{{ {self.raw=}, {self.type=}, {self.pubKey=} }}'
    
    def __repr__(self):
        return str(self)

class Output:
    def __init__(self, raw):
        self.raw = raw

        satoshis_hex = raw[:16]
        raw = raw[16:] 
        satoshis_hex_rev = int('0x' + satoshis_hex, 16).to_bytes(8, byteorder='little').hex()
        self.satoshis =  int('0x' + satoshis_hex_rev, 16)

        output_bytes, raw = parseVarint(raw)
        output_len = output_bytes * 2
        self.scriptPubKey = ScriptPubKey(raw[:output_len]);

        raw = raw[output_len:]

        self.raw = self.raw[:len(self.raw) - len(raw)]
  
    def __str__(self):
        return f'{{ {self.raw=}, {self.satoshis=}, {self.scriptPubKey=} }}'
    
    def __repr__(self):
        return str(self)    

class PubKeySigMsg:
    def __init__(self, pub_key: str, rs: tuple[int, int], z: int):
        self.pubKey = pub_key
        self._pubKeyPoint = None
        self.rs = rs
        self.z = z   

    def verify(self):
        from btc import Btc
        from secp256k1 import secp

        if self._pubKeyPoint == None:
            self._pubKeyPoint = Btc.publicKeyHexToSecpPoint(self.pubKey)

        return secp.verifySignature(self._pubKeyPoint, prsz.z, prsz.rs)
        
    def __str__(self):
        return f'{{ {self.pubKey=}, {self.rs=}, {self.z=} }}'
    
    def __repr__(self):
        return str(self)  
    
class Trx:

    def __init__(self, id: str = None, is_test: bool = False):

        self.id = id
        self.isTest = is_test
        
        if (self.id):
            slug = 'testnet/' if self.isTest else ''

            import urllib.request
            result = urllib.request.urlopen('https://mempool.space/' + slug + 'api/tx/' + self.id + '/hex').read()

            self.setRaw(result.decode('utf-8'), self.isTest)
    
    def setRaw(self, raw: str, is_test: bool = False):

        self.raw = raw
        self.isTest = is_test

        self._parseRaw()

        self._pkMsgs = None
        
    @staticmethod
    def _extractScriptPubKey(trx_id: str, vout: int):
        pass # TODO

    def _parseInputs(self, raw: str):
        offset = len(self.raw) - len(raw)

        self.inputs: list[Input] = []

        # Extract the all inputs and the start / end indices of the corresponding script sig sections
        for i in range(self.inputCount):
            input = Input(raw, offset)
            self.inputs.append(input)

            offset2 = len(input.raw)
            raw = raw[offset2:]
            offset += offset2

            #print('sigscript', self.raw[input.sigScript.startIndex:input.sigScript.endIndex])

        return raw
    
    def _parseOutputs(self, raw: str):
        self.outputs: list[Output] = []

        for i in range(self.outputCount):
            output = Output(raw)
            self.outputs.append(output)
            raw = raw[len(output.raw):]

        return raw
    
    def _parseRaw(self):
        raw = self.raw
        raw = raw[8:] # remove version
    
        self.usesSegWit = raw.startswith('00')
        if self.usesSegWit:
            raw = raw[4:]
            raise Exception('segregated witness transactions are not fully implemented')
    
        self.inputCount, raw = parseVarint(raw)
        raw = self._parseInputs(raw)
        '''
        print(self.raw)
        print(self.inputCount)
        print(self.inputs)
        '''
        self.outputCount, raw = parseVarint(raw)
        raw = self._parseOutputs(raw)

        if not raw.endswith('00000000'):
            raise Exception('missing transaction end sequence')

    def __str__(self):
        return f'{{ {self.id=}, {self.raw=}, {self.inputCount=}, {self.inputs=}, {self.outputCount=}, {self.outputs=}, {self.usesSegWit=} }}'
    
    def __repr__(self):
        return str(self)    
    
    def _getPkMsgs(self):
        from btc import hash160
        
        if self._pkMsgs == None:
            
            sig_script_indices = []
            for i in range(self.inputCount):
                input = self.inputs[i]

                '''
                a = input.sigScript.startIndex
                b = input.sigScript.endIndex

                print(self.raw[a:b])
                '''

                sig_script_indices.append((input.sigScript.startIndex, input.sigScript.endIndex))

            sig_script_indices_reversed = sig_script_indices.copy()
            sig_script_indices_reversed.reverse()                

            #print(sig_script_indices_reversed)

            self._pkMsgs = []
            for i in range(self.inputCount):
                raw = self.raw
                
                input = self.inputs[i]

                # get the script pubkey of the prev_trx vout
                prev_trx = Trx(input.prevTrxId, self.isTest)
                prev_trx_output = prev_trx.outputs[input.prevTrxVout]   

                prev_trx_output_script_pubkey = prev_trx_output.scriptPubKey.raw
                pubkey_byte_len_hex = hex(len(prev_trx_output_script_pubkey) >> 1)[2:] # the half length is the byte length; remove 0x

                #print('19 or not', f'{pubkey_byte_len_hex=}')
        
                for script_sig_start_index2, script_sig_end_index2 in sig_script_indices_reversed:

                    raw_first = raw[:script_sig_start_index2]
                    raw_second = raw[script_sig_end_index2:]

                    if script_sig_start_index2 == input.sigScript.startIndex:
                        # insert pubkey length and pubkey
                        insertion = pubkey_byte_len_hex + prev_trx_output_script_pubkey 
                    else: # replace other script sigs with 0x0
                        insertion = '00'
                
                    raw = raw_first + insertion + raw_second

                raw += input.sigScript.signature.hashingSequence # add the SIGHASH sequence
         
                #print('msg', raw)            

                # generate hash160 from msg and store it
                msg_hex = hash160(bytes(bytearray(raw, 'ascii')))

                self._pkMsgs.append((prev_trx_output.scriptPubKey.pubKey, int(msg_hex, 16)))

        return self._pkMsgs
    
    def _getSignatureData(self) -> list: 

        tprs = []
        for i in range(self.inputCount):
            sig_script = self.inputs[i].sigScript
            signature = sig_script.signature

            tprs.append(((sig_script.type, sig_script.pubKey), ((int(signature.r, 16), int(signature.s, 16)))))

        return tprs

    def getPubKeySigMsgList(self, pub_key: str = None) -> list[PubKeySigMsg]:
        
        prsz: list[PubKeySigMsg] = []

        tps_rs = self._getSignatureData()
        pb_msg = self._getPkMsgs()

        l = list(zip(tps_rs, pb_msg))
        for i in range(len(l)):
            ((t, ps), rs), (pb, msg) = l[i]

            if t == ScriptType.P2PK:
                p = pb
            else:
                p = ps

            if pub_key == None or pub_key == p:
                prsz.append(PubKeySigMsg(p, rs, msg))    

        return prsz

if __name__ == '__main__':

    #trx1 = Trx('a3cf0c4dd6c5dc905936785fa1685cce5c7f99970bae4f2bd417896967c2b305')
    #print(trx1)

    #trx2 = Trx()
    #trx2.setRaw('01000000012fc93dc03d05e450603e354be409cba8e74a75aece39e0e72ce32fe288350972010000006b483045022100c378e5e472769ea116ee84f24917d245659e3596c71a66a4ae75cb9f9fa046d702204b3942cc040ea596f9e9950775c5165b379a5f6857137d8d921c39978b6fa5ee012102bf8135821ba2d6a13a0028f405e55b0e8262f683f59f6b4b348bcc043185efa5ffffffff02394012000000000017a914847d516dc58631a6ec2b87d60854aae894b52c9e87f23a29000000000017a914a047f94cd407ae34820bdf81070da1a2955174098700000000') 
    #print(trx2)
    
    #prev_trx = Trx('72093588e22fe32ce7e039ceae754ae7a8cb09e44b353e6050e4053dc03dc92f')
    #print(prev_trx)

    #trx2.getScriptSigMsgs()

    test_trx = Trx()
    test_trx.setRaw('020000000255a736179f5ee498660f33ca6f4ce017ed8ad4bd286c162400d215f3c5a876af000000006b483045022100f33bb5984ca59d24fc032fe9903c1a8cb750e809c3f673d71131b697fd13289402201d372ec7b6dc6fda49df709a4b53d33210bfa61f0845e3253cd3e3ce2bed817e012102EE04998F8DBD9819D0391A5AA38DB1331B0274F64ABC3BC66D69EE61DB913459ffffffff4d89764cf5490ac5023cb55cd2a0ecbfd238a216de62f4fd49154253f1a75092020000006a47304402201f055eb8374aca9b779dd7f8dc91e0afb609ac61cd5cb9ad1f9ca0359c3d134a022019c45145919394096e42963b7e9b6538cdb303a30c6ff0f17b8b0cfb1e897f5a01210333D23631BC450AAF925D685794903576BBC8B20007CF334C0EA6C7E2C0FAB2BAffffffff0200e20400000000001976a914e993470936b573678dc3b997e56db2f9983cb0b488ac20cb0000000000001976a914b780d54c6b03b053916333b50a213d566bbedd1388ac00000000', True)

    prsz_list = test_trx.getPubKeySigMsgList()

    for i in range(len(prsz_list)):
        prsz = prsz_list[i]
        print('Is signature correct:', prsz.verify())
'''
    prsz_list = test_trx.getPubKeySigMsgList('02EE04998F8DBD9819D0391A5AA38DB1331B0274F64ABC3BC66D69EE61DB913459')
    prsz = prsz_list[0]  
    
    print('Is signature correct:', prsz.verify())

    ###

    trx = Trx()
    trx.setRaw('0100000001a4e61ed60e66af9f7ca4f2eb25234f6e32e0cb8f6099db21a2462c42de61640b010000006b483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31feffffff02f9243751130000001976a9140c443537e6e31f06e6edb2d4bb80f8481e2831ac88ac14206c00000000001976a914d807ded709af8893f02cdc30a37994429fa248ca88ac751a0600')
    trx = Trx(trx.id)  
    
    prsz_list = trx.getPubKeySigMsgList(Btc.wifToHash160('18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8'))
    print('Signatures for trx ' + trx.id + ':', len(prsz_list))
    for prsz in prsz_list:
        print('Is signature correct:', prsz.verify())
    
    prev_trx = Trx('72093588e22fe32ce7e039ceae754ae7a8cb09e44b353e6050e4053dc03dc92f')
    
    prsz_list = prev_trx.getPubKeySigMsgList()

    for i in range(len(prsz_list)):
        prsz = prsz_list[i]
        
        print('Is signature correct:', prsz.verify())
