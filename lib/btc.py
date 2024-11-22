import hashlib
import base58
import codecs

'''
if __package__:
    from .secp256k1 import curve, scalar_mult
else:
    from secp256k1 import curve, scalar_mult
'''

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

from secp256k1 import curve, scalar_mult

def hash256(hex: bytes) -> bytes:
    """Returns the hex input hash160'ed hex bytes"""

    bin = codecs.decode(hex, 'hex')

    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()

    return codecs.encode(hash2, 'hex')

def addHash160Checksum(hex: bytes) -> bytes:
    """Attaches the hash160 checksum of the hex bytes input to its end and returns the result as binary bytes"""

    hash2_hex = hash256(hex)
    checksum = hash2_hex[:8]
    hex += checksum

    return codecs.decode(hex, 'hex')
    
def uncompress_privkey(privkey_wif_compressed: str) -> str:

    privkey_bin = base58.b58decode(privkey_wif_compressed)
    privkey_hex = codecs.encode(privkey_bin, 'hex')

    privkey_hex = privkey_hex[:-8] # remove the checksum

    if privkey_hex.endswith(b"01"): # The private key indicates that the public key should get compressed 
        privkey_hex = privkey_hex[:-2]
        privkey_bin = addHash160Checksum(privkey_hex)

        # convert private_key into base58 encoded string
        privkey_wif_uncompressed = base58.b58encode(privkey_bin).decode('utf-8')
    
        return privkey_wif_uncompressed
    else:
        return privkey_wif_compressed

def compute_pubkey_address(pubkey: str) -> str:

    # Converting to binary for SHA-256 hashing
    pubkey_bin = codecs.decode(pubkey, 'hex')

    sha = hashlib.sha256(pubkey_bin)

    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    key_hash = rip.hexdigest()

    modified_key_hash = "00" + key_hash # 00 for main net

    byte_25_address = addHash160Checksum(bytes(bytearray(modified_key_hash, 'ascii')))

    address = base58.b58encode(byte_25_address).decode('utf-8')

    return address
    
def compress_pubkey(pubkey: str) -> str:

    # check if the last byte is odd or even
    if (ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0):
        public_key_compressed = '02'
    else:
        public_key_compressed = '03'
        
    # add the 32 bytes of the x-coord
    public_key_compressed += pubkey[:64]

    return public_key_compressed

def privateHexKeyToWif(privkey_hex: str, compress: bool = True, mainnet = True) -> str:

    if mainnet: variant = '80' 
    else: variant = 'ef'
    
    privkey_hex = variant + privkey_hex
    
    if compress: privkey_hex += '01'

    privkey_bytes = bytes(bytearray(privkey_hex, 'ascii'))

    privkey_bin = addHash160Checksum(privkey_bytes)
    privkey_wif = base58.b58encode(privkey_bin).decode('utf-8')

    return privkey_wif

def privateWifKeyToHex(privkey_wif: str) -> str:

    privkey_wif_uncompressed = uncompress_privkey(privkey_wif)

    privkey_hex = codecs.encode(base58.b58decode(privkey_wif_uncompressed), 'hex')
    privkey_hex = privkey_hex[2:-8] # remove net identifier and checksum  
  
    return codecs.decode(privkey_hex) # byte literal to string

def privateKeyToPublicKeyWif(privkey: str) -> str:

    if len(privkey) != 64: # 64 chars is hex
        privkey = privateWifKeyToHex(privkey)

    privkey_int = int(privkey, 16)

    x, y = scalar_mult(privkey_int, curve.g) # or use: ecdsa.SigningKey.from_string(privkey_bin, curve=ecdsa.SECP256k1).verifying_key

    #print("\nCoords of the public key:", (x, y))

    x_hex = hex(x)[2:]
    y_hex = hex(y)[2:] 

    pubkey = x_hex + y_hex

    pubkey_address_uncompressed = compute_pubkey_address('04' + pubkey) 
    pubkey_compressed = compress_pubkey(pubkey)
    pubkey_address_compressed = compute_pubkey_address(pubkey_compressed)

    return (pubkey_address_compressed, pubkey_address_uncompressed)

def wifToHash160(wif: str) -> str:

    address_bin = base58.b58decode(wif)
    hash_hex = codecs.encode(address_bin, 'hex')
    hash160 = codecs.decode(hash_hex[2:42])

    return hash160

def extractSigDataFromScriptSig(script_sig: str) -> list[int]:

    if not script_sig.startswith('4830'):
        raise Exception('invalid scriptSig')
        
    script_sig = script_sig[4:146] # extract the signature + two byte end sequence
 
    if not script_sig.endswith('01'):
        raise('invalid script sig')
    
    script_sig = script_sig[:-2] # remove the end sequence

    total_len, script_sig = parseVarint(script_sig)

    script_sig = script_sig[2:] # remove first type specifier

    first_len_bytes, script_sig = parseVarint(script_sig)
    first_len_hex_chars = 2 * first_len_bytes
    
    r = script_sig[:first_len_hex_chars]
    script_sig = script_sig[first_len_hex_chars:] # remove r
   
    script_sig = script_sig[2:] # remove second type specifier

    sec_len_bytes, script_sig = parseVarint(script_sig)
    sec_len_hex_chars = 2 * sec_len_bytes

    s = script_sig[:sec_len_hex_chars]
    script_sig = script_sig[sec_len_hex_chars:] # remove s
    
    if total_len - first_len_bytes - sec_len_bytes - 4 != 0:
        raise Exception('scriptSig length mismatch')

    return int(r, 16), int(s, 16)

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

def parseInputs(trx: str) -> list:
    trx = trx[8:] # remove version
    
    if trx.startswith('00'):
        trx = trx[4]
        raise('segregated witness transactions are not implemented')
    
    return parseVarint(trx)

def extractPreviousTrxIdVout(trx: str):

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

def fetchTransaction(trx_id: str):

    import urllib.request
    result = urllib.request.urlopen('https://learnmeabitcoin.com/explorer/download.php?tx=' + trx_id + '&type=json').read()

    import json
    contents = json.loads(result)
    #print(contents['scriptPubKey'])
    return contents #['hex']

def extractScriptPubKey(trx_id: str, vout: int):

    # fetch the scriptPubKey of the previous trx vout
    trx_prev = fetchTransaction(trx_id)
    print('prev trx = ', trx_prev['vout'])

def extractPubkeysAndScriptSigIndices(trx: str):
    
    # Backup the trx
    trx_bak = trx

    # Get the input count
    inputs, trx = parseInputs(trx)

    pubkey_script_sig_idx = []

    # Extract the "public keys" (P2PK <-> P2PKH <-> P2SH) of all inputs and the start / end indices of the corresponding script sig sections
    for i in range(inputs):
        trx_prev_id_vout, trx = extractPreviousTrxIdVout(trx)

        #spk = extractScriptPubKey(*trx_prev_id_vout)

        script_sig_start_index = len(trx_bak) - len(trx)

        script_sig_bytes, trx = parseVarint(trx)
        sig_bytes, trx = parseVarint(trx)

        trx = trx[sig_bytes * 2:] # remove the sig

        pubkey_bytes, trx = parseVarint(trx)
        pubkey_len = pubkey_bytes * 2

        pubkey = trx[:pubkey_len]
        trx = trx[pubkey_len:] # remove the pubkey

        script_sig_end_index = len(trx_bak) - len(trx)
        pubkey_script_sig_idx.append([ pubkey, script_sig_start_index, script_sig_end_index ])

        #print(trx_bak[script_sig_start_index:script_sig_end_index])
        
        trx = trx[8:] # remove end sequence

    return pubkey_script_sig_idx

def getSignatureHashingSequence(signature: str) -> str:
            
    script_sig_len, signature = parseVarint(signature)
    sig_len, signature = parseVarint(signature) 
    sig_len *= 2

    signature_last_2chars = signature[sig_len - 2:sig_len]

    if signature_last_2chars not in [ '01', '02', '03' ]:
        raise Exception('ANYONECANPAY signature handling is not implemented')

    sequence = int('0x' + signature_last_2chars, 16).to_bytes(4, byteorder='little').hex()

    return sequence

def getScriptSigMsgs(trx: str):
    
    # Backup the trx
    trx_bak = trx

    pubkey_script_sig_idx = extractPubkeysAndScriptSigIndices(trx)
    print(f'{pubkey_script_sig_idx=}')

    msgs = []

    for pubkey, script_sig_start_index, script_sig_end_index in pubkey_script_sig_idx:
        trx = trx_bak

        #print(script_sig_start_index)

        pubkey_script_sig_idx_reversed = pubkey_script_sig_idx
        pubkey_script_sig_idx_reversed.reverse()

        #print(pubkey_script_sig_idx_reversed)

        for pubkey2, script_sig_start_index2, script_sig_end_index2 in pubkey_script_sig_idx_reversed:

            trx_first = trx[:script_sig_start_index2]
            trx_second = trx[script_sig_end_index2:]

            if script_sig_start_index2 == script_sig_start_index:
                pubkey_byte_len = hex(len(pubkey) >> 1)
                # insert pubkey length and pubkey
                insertion = pubkey_byte_len[2:] + pubkey
            else: # replace other script sigs with 0x0
                insertion = '00'
        
            trx = trx_first + insertion + trx_second

        signature = trx_bak[script_sig_start_index:script_sig_end_index]     
        trx += getSignatureHashingSequence(signature) # add the SIGHASH sequence

        #print(trx)            

        # generate hash256 msg and store it
        msg_hex = hash256(bytes(bytearray(trx, 'ascii')))

        msgs.append(int(msg_hex, 16))

    return msgs

def extractSigDataFromTransaction(trx: str) -> list: 
    inputs, trx = parseInputs(trx)

    rs = []
    for i in range(inputs):
        trx_prev_id_vout, trx = extractPreviousTrxIdVout(trx)

        script_sig_size, trx = parseVarint(trx)
      
        script_sig_size *= 2
        script_sig = trx[:script_sig_size]
        trx = trx[script_sig_size:]

        rs.append(extractSigDataFromScriptSig(script_sig))
        trx = trx[8:] # remove end sequence

    return rs

def getRszFromTrx(trx: str): 
    rs = extractSigDataFromTransaction(trx)
    msg = getScriptSigMsgs(trx)

    return list(zip(rs, msg))

####################################################################################

if __name__ == '__main__':

    #print(privateKeyToPublicKeyWif('7e0dd9f1fb3c11c0b7b555b7f9115d63361283b4073472fa4055f2d765344113'))
    #print(privateKeyToPublicKeyWif('L2BYcYFgqjBtWASZyC7oScc7tdtBytZXvF6NGzmTRUupMiCMCrpC'))
    #print(privateKeyToPublicKeyWif('5KhW6aAcyTjTvzvVSgnkd1P1q2BLWXg1jtK1U124sknzxNTbxHm'))
    
    #print(privateHexKeyToWif('7e0dd9f1fb3c11c0b7b555b7f9115d63361283b4073472fa4055f2d765344113'))

    #print(wifToHash160('n2ozAmaunMGwPDjtxmZsyxDRjYAJqmZ6Dk'))

    #print(extractSigDataFromScriptSig('483045022100b8e920e1573578b5c2dd84864fce6f0681d7753b266c59682179a00c05c76d8d02201d372ec7b6dc6fda49df709a4b53d33210bfa61f0845e3253cd3e3ce2bed817e012102EE04998F8DBD9819D0391A5AA38DB1331B0274F64ABC3BC66D69EE61DB913459'))

    trx = '01000000012fc93dc03d05e450603e354be409cba8e74a75aece39e0e72ce32fe288350972010000006b483045022100c378e5e472769ea116ee84f24917d245659e3596c71a66a4ae75cb9f9fa046d702204b3942cc040ea596f9e9950775c5165b379a5f6857137d8d921c39978b6fa5ee012102bf8135821ba2d6a13a0028f405e55b0e8262f683f59f6b4b348bcc043185efa5ffffffff02394012000000000017a914847d516dc58631a6ec2b87d60854aae894b52c9e87f23a29000000000017a914a047f94cd407ae34820bdf81070da1a2955174098700000000'

    #print(getScriptSigMsgs(trx))
    #print(extractSigDataFromTransaction(trx))

    print(getRszFromTrx(trx))