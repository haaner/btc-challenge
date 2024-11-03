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

def double_sha256_checksum(hex: bytes) -> bytes:
    """Double sha256 function returning the checksum attached to input as binary"""

    bin = codecs.decode(hex, 'hex')

    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()
    
    hash2_hex = codecs.encode(hash2, 'hex')

    checksum = hash2_hex[:8]
    hex += checksum

    return codecs.decode(hex, 'hex')
    
def uncompress_privkey(privkey_wif_compressed: str) -> str:

    privkey_bin = base58.b58decode(privkey_wif_compressed)
    privkey_hex = codecs.encode(privkey_bin, 'hex')

    privkey_hex = privkey_hex[:-8] # remove the checksum

    if privkey_hex.endswith(b"01"): # The private key indicates that the public key should get compressed 
        privkey_hex = privkey_hex[:-2]
        privkey_bin = double_sha256_checksum(privkey_hex)

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

    byte_25_address = double_sha256_checksum(bytes(bytearray(modified_key_hash, 'ascii')))

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

    privkey_bin = double_sha256_checksum(privkey_bytes)
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

    return r, s

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

        byteval = varint[0:count]
        intval = int('0x' + byteval, 16)
        varint = varint[count:]
        
    return (intval, varint)

def extractSigDataFromTransaction(trx: str) -> list[list[int]]: 

    trx = trx[8:] # remove version
    
    if trx.startswith('00'):
        trx = trx[4]
        raise('segregated witness transaction are not implemented')
    
    inputs, trx = parseVarint(trx)

    trx = trx[72:] # remove prev transaction id and vout

    rs = []
    for i in range(inputs):
        script_sig_size, trx = parseVarint(trx)
      
        script_sig_size *= 2
        script_sig = trx[:script_sig_size]
        trx = trx[script_sig_size:]

        rs.append(extractSigDataFromScriptSig(script_sig))
        trx = trx[8:] # remove end sequence

    return rs

####################################################################################

if __name__ == '__main__':

    #print(privateKeyToPublicKeyWif('7e0dd9f1fb3c11c0b7b555b7f9115d63361283b4073472fa4055f2d765344113'))
    #print(privateKeyToPublicKeyWif('L2BYcYFgqjBtWASZyC7oScc7tdtBytZXvF6NGzmTRUupMiCMCrpC'))
    #print(privateKeyToPublicKeyWif('5KhW6aAcyTjTvzvVSgnkd1P1q2BLWXg1jtK1U124sknzxNTbxHm'))
    
    #print(privateHexKeyToWif('7e0dd9f1fb3c11c0b7b555b7f9115d63361283b4073472fa4055f2d765344113'))

    #print(wifToHash160('n2ozAmaunMGwPDjtxmZsyxDRjYAJqmZ6Dk'))

    print(extractSigDataFromScriptSig('483045022100b8e920e1573578b5c2dd84864fce6f0681d7753b266c59682179a00c05c76d8d02201d372ec7b6dc6fda49df709a4b53d33210bfa61f0845e3253cd3e3ce2bed817e012102EE04998F8DBD9819D0391A5AA38DB1331B0274F64ABC3BC66D69EE61DB913459'))