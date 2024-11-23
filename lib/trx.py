if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

def parseVarint(varint: str) -> list: 

    first_byte = varint[0:2]
    varint = varint[2:]

    intval = int('0x' + first_byte, 16)

    if intval <= 0xfc:
        pass
    else:
        if intval <= 0xfd:
            count = 4
        elif intval <= 0xfe:
            count = 8
        else:
            count = 16

        byteval = varint[0:count+1] # fix
        intval = int('0x' + byteval, 16)
        varint = varint[count:]
        
    return (intval, varint)

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
            self.type = 'P2SH'

            op_code, script_sig = Operation.parseCode(script_sig)
            if op_code != Operation.PUSHBYTES_71:
                raise Exception('unknown unlocking script')
            
            self.signature = script_sig[:142]
            script_sig = script_sig[142:]
            
            op_code, script_sig = Operation.parseCode(script_sig)
            if op_code != Operation.PUSHBYTES_71:
                raise Exception('unknown unlocking script')

            script_sig = script_sig[142:]
            if script_sig != '':
                raise Exception('unknown unlocking script')
                            
        elif op_code in [ Operation.PUSHBYTES_71, Operation.PUSHBYTES_72, Operation.PUSHBYTES_73 ]:

            byte_count = int('0x' + op_code, 16);
            char_count = byte_count * 2

            self.signature = script_sig[:char_count]
            script_sig = script_sig[char_count:]

            if op_code == Operation.PUSHBYTES_71 and script_sig == '':
                self.type = 'P2PK' 
            else:
                self.type = 'P2PKH'

                op_code, script_sig = Operation.parseCode(script_sig)
                if op_code in [ Operation.PUSHBYTES_33, Operation.PUSHBYTES_65 ]:

                    byte_count = int('0x' + op_code, 16);
                    char_count = byte_count * 2

                    script_sig = script_sig[char_count:]
                    if script_sig != '':
                        raise Exception('unknown unlocking script')
                else:
                    raise Exception('unknown unlocking script')
            
        else:
            raise Exception('unknown unlocking script') # TODO Nested Segwit / Native Segwit

    def getHashingSequence(self) -> str:        
        sig_len = len(self.signature)

        signature_last_2chars = self.signature[sig_len - 2:sig_len]

        if signature_last_2chars not in [ '01', '02', '03' ]:
            raise Exception('ANYONECANPAY signature handling is not implemented')

        sequence = int('0x' + signature_last_2chars, 16).to_bytes(4, byteorder='little').hex()

        return sequence
        
    def __str__(self):
        return f'{{ {self.raw=}, {self.startIndex=}, {self.endIndex=}, {self.type=}, {self.signature=} }}'
    
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
            self.type = 'P2SH'
            
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.PUSHBYTES_20:
                raise Exception('unknown locking script')
            
            self.pubKey = raw[:40]
            raw = raw[40:]
        
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.EQUAL:
                raise Exception('unknown locking script end sequence')
            
        elif op_code == Operation.PUSHBYTES_65: 
            self.type = 'P2PK'
            
            self.pubKey = raw[:130]
            raw = raw[130:]
        
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.CHECKSIG:
                raise Exception('unknown locking script end sequence')
            
        elif op_code == Operation.DUP: 
            self.type = 'P2PKH'

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
                self.type = 'P2WPKH'
                
                self.pubKey = raw[:40]
                raw = raw[40:]

            elif op_code == Operation.PUSHBYTES_32:
                self.type = 'P2WSH'
                
                self.pubKey = raw[:64]
                raw = raw[64:]

            else:
                raise Exception('unknown locking script')

        elif op_code == Operation.ONE:             
            self.type = 'P2TR'

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

class Trx:

    def __init__(self, id: str = None):
        self.id = id
        
        if (self.id):
            import urllib.request
            result = urllib.request.urlopen('https://learnmeabitcoin.com/explorer/download.php?tx=' + id + '&type=json').read()

            import json
            contents = json.loads(result)

            self.setRaw(contents['hex'])
    
    def setRaw(self, raw: str):
        self.raw = raw
        self._parseRaw()

        self._msgs = None
        
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
    
    def getScriptSigMsgs(self):
        from btc import hash256
        
        if self._msgs == None:
            
            sig_script_indices = []
            for i in range(self.inputCount):
                input = self.inputs[i]

                '''
                a = input.sigScript.startIndex
                b = input.sigScript.endIndex

                print(self.raw[a:b])
                '''

                sig_script_indices.append((input.sigScript.startIndex, input.sigScript.endIndex))

            self._msgs = []
            for i in range(self.inputCount):
                raw = self.raw
                
                input = self.inputs[i]

                # get the script pubkey of the prev_trx vout
                prev_trx = Trx(input.prevTrxId)
                prev_trx_output = prev_trx.outputs[input.prevTrxVout]   

                prev_trx_output_script_pubkey = prev_trx_output.scriptPubKey.raw
                pubkey_byte_len_hex = hex(len(prev_trx_output_script_pubkey) >> 1)[2:] # the half length is the byte length; remove 0x

                #print('19 or not', f'{pubkey_byte_len_hex=}')
        
                sig_script_indices_reversed =  sig_script_indices
                sig_script_indices_reversed.reverse()

                #print(sig_script_indices_reversed)

                for script_sig_start_index2, script_sig_end_index2 in sig_script_indices_reversed:

                    raw_first = raw[:script_sig_start_index2]
                    raw_second = raw[script_sig_end_index2:]

                    if script_sig_start_index2 == input.sigScript.startIndex:
                        # insert pubkey length and pubkey
                        insertion = pubkey_byte_len_hex + prev_trx_output_script_pubkey 
                    else: # replace other script sigs with 0x0
                        insertion = '00'
                
                    raw = raw_first + insertion + raw_second

                raw += input.sigScript.getHashingSequence() # add the SIGHASH sequence
                #print(raw)            

                # generate hash256 msg and store it
                msg_hex = hash256(bytes(bytearray(raw, 'ascii')))

                self._msgs.append(int(msg_hex, 16))

        return self._msgs
    
if __name__ == '__main__':

    #trx1 = Trx('a3cf0c4dd6c5dc905936785fa1685cce5c7f99970bae4f2bd417896967c2b305')
    #print(trx1)

    #trx2 = Trx()
    #trx2.setRaw('01000000012fc93dc03d05e450603e354be409cba8e74a75aece39e0e72ce32fe288350972010000006b483045022100c378e5e472769ea116ee84f24917d245659e3596c71a66a4ae75cb9f9fa046d702204b3942cc040ea596f9e9950775c5165b379a5f6857137d8d921c39978b6fa5ee012102bf8135821ba2d6a13a0028f405e55b0e8262f683f59f6b4b348bcc043185efa5ffffffff02394012000000000017a914847d516dc58631a6ec2b87d60854aae894b52c9e87f23a29000000000017a914a047f94cd407ae34820bdf81070da1a2955174098700000000') 
    #print(trx2)
    
    #prev_trx = Trx('72093588e22fe32ce7e039ceae754ae7a8cb09e44b353e6050e4053dc03dc92f')
    #print(prev_trx)

    #trx2.getScriptSigMsgs()

    test_trx = Trx('1eea8850090f170bc0e9557a04c9547bf9470941017526a68ae5e36e26bad9b3')
    #test_trx.setRaw('020000000255a736179f5ee498660f33ca6f4ce017ed8ad4bd286c162400d215f3c5a876af000000006b483045022100f33bb5984ca59d24fc032fe9903c1a8cb750e809c3f673d71131b697fd13289402201d372ec7b6dc6fda49df709a4b53d33210bfa61f0845e3253cd3e3ce2bed817e012102EE04998F8DBD9819D0391A5AA38DB1331B0274F64ABC3BC66D69EE61DB913459ffffffff4d89764cf5490ac5023cb55cd2a0ecbfd238a216de62f4fd49154253f1a75092020000006a47304402201f055eb8374aca9b779dd7f8dc91e0afb609ac61cd5cb9ad1f9ca0359c3d134a022019c45145919394096e42963b7e9b6538cdb303a30c6ff0f17b8b0cfb1e897f5a01210333D23631BC450AAF925D685794903576BBC8B20007CF334C0EA6C7E2C0FAB2BAffffffff0200e20400000000001976a914e993470936b573678dc3b997e56db2f9983cb0b488ac20cb0000000000001976a914b780d54c6b03b053916333b50a213d566bbedd1388ac00000000')

    print(test_trx)

   