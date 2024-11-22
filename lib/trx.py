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
    HASH160 = 'a9'
    PUSHBYTES_20 = '14'
    EQUAL = '87'
    PUSHBYTES_65 = '41'
    CHECKSIG = 'ac'
    DUP = '76'
    EQUALVERIFY = '88'

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
        sig_bytes, raw = parseVarint(raw)

        sig_len = sig_bytes * 2
        self.signature = raw[:sig_len]
        raw = raw[sig_len:] # remove the signature

        pubkey_bytes, raw = parseVarint(raw)
        pubkey_len = pubkey_bytes * 2

        self.pubkey = raw[:pubkey_len]
        raw = raw[pubkey_len:] # remove the pubkey

        self.endIndex = self.startIndex + len(self.raw) - len(raw)
        raw = raw[8:] # remove end sequence

        self.raw = self.raw[:len(self.raw) - len(raw)]
   
    def __str__(self):
        return f'{{ {self.raw=}, {self.startIndex=}, {self.endIndex=}, {self.signature=}, {self.pubkey=} }}'
    
    def __repr__(self):
        return str(self)

class Input:
    def __init__(self, raw, offset):
        self.raw = raw

        (self.prevTrxId, self.prevTrxVout), raw = self._extractPreviousTrxIdVout(raw)

        #spk = self._extractScriptPubKey(*trx_prev_id_vout)
        offset2 = len(self.raw) - len(raw)
        self.sigScript = ScriptSig(raw, offset + offset2)

        self.raw = self.raw[:offset2 + len(self.sigScript.raw)]

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

        if op_code == Operation.HASH160: # P2SH
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.PUSHBYTES_20:
                raise('unknown locking script')
            
            self.pubKey = raw[:40]
            raw = raw[40:]
        
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.EQUAL:
                raise('unknown locking script end sequence')
            
        elif op_code == Operation.PUSHBYTES_65: # P2PK
            self.pubKey = raw[:130]
            raw = raw[130:]
        
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.CHECKSIG:
                raise('unknown locking script end sequence')
            
        elif op_code == Operation.DUP: # P2PKH
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.HASH160:
                raise('unknown locking script')
            
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.PUSHBYTES_20:
                raise('unknown locking script')
            
            self.pubKey = raw[:40]
            raw = raw[40:]
        
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.EQUALVERIFY:
                raise('unknown locking script end sequence')
            
            op_code, raw = Operation.parseCode(raw)
            if op_code != Operation.CHECKSIG:
                raise('unknown locking script end sequence')
            
        else:
            raise('unknown locking script')     

        self.raw = self.raw[:len(self.raw) - len(raw)]           
        
    def __str__(self):
        return f'{{ {self.raw=}, {self.pubKey=} }}'
    
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
            self.raw = contents['hex']

            self._parseRaw()

    def setRaw(self, raw: str):
        self.raw = raw
        self._parseRaw()
        
    @staticmethod
    def _extractScriptPubKey(trx_id: str, vout: int):
        pass # TODO

    def _parseInputs(self, raw: str):
        offset = len(self.raw) - len(raw)

        # Backup the raw data
        raw_bak = raw

        self.inputs = []

        # Extract the "public keys" (P2PK <-> P2PKH <-> P2SH) of all inputs and the start / end indices of the corresponding script sig sections
        for i in range(self.inputCount):
            input = Input(raw, offset)
            self.inputs.append(input)

            offset2 = len(input.raw)
            raw = raw[offset2:]
            offset += offset2

        return raw
    
    def _parseOutputs(self, raw: str):
        self.outputs = []

        for i in range(self.outputCount):
            output = Output(raw)
            self.outputs.append(output)
            raw = raw[len(output.raw):]

        return raw
    
    def _parseRaw(self):
        raw = self.raw
        raw = raw[8:] # remove version
    
        if raw.startswith('00'):
            raw = raw[4]
            raise('segregated witness transactions are not implemented')
    
        self.inputCount, raw = parseVarint(raw)
        raw = self._parseInputs(raw)

        self.outputCount, raw = parseVarint(raw)
        raw = self._parseOutputs(raw)

        if not raw.endswith('00000000'):
            raise('missing transaction end sequence')

    def __str__(self):
        return f'{{ {self.id=}, {self.raw=}, {self.inputCount=}, {self.inputs=}, {self.outputCount=}, {self.outputs=} }}'
    
if __name__ == '__main__':

    #trx1 = Trx('a3cf0c4dd6c5dc905936785fa1685cce5c7f99970bae4f2bd417896967c2b305')
    #print(trx1)

    trx2 = Trx()
    trx2.setRaw('01000000012fc93dc03d05e450603e354be409cba8e74a75aece39e0e72ce32fe288350972010000006b483045022100c378e5e472769ea116ee84f24917d245659e3596c71a66a4ae75cb9f9fa046d702204b3942cc040ea596f9e9950775c5165b379a5f6857137d8d921c39978b6fa5ee012102bf8135821ba2d6a13a0028f405e55b0e8262f683f59f6b4b348bcc043185efa5ffffffff02394012000000000017a914847d516dc58631a6ec2b87d60854aae894b52c9e87f23a29000000000017a914a047f94cd407ae34820bdf81070da1a2955174098700000000') 
    print(trx2)
