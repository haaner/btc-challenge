import base58
import codecs
import hashlib

from os import urandom
import random

'''
if __package__:
    from .secp256k1 import curve, scalar_mult
else:
    from secp256k1 import curve, scalar_mult
'''

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

def doubleSha256(hex: bytes) -> bytes:
    """Returns the hex input doubleSha256'ed hex bytes"""

    bin = codecs.decode(hex, 'hex')

    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()

    return codecs.encode(hash2, 'hex')

def hash160(hex_str: str):
    bin = codecs.decode(hex_str, 'hex') 

    sha = hashlib.sha256(bin)
    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())

    return rip.hexdigest()

from secp256k1 import secp, Point

class Btc:

    PRIVATE_KEY_PREFIX_TESTNET = {
        '80': False,
        'ef': True
    }

    def _getPrivateKeyPrefix(for_testnet = False):
        dic = Btc.PRIVATE_KEY_PREFIX_TESTNET
        return list(dic.keys())[list(dic.values()).index(for_testnet)]
    
    def _isTestNetKeyPrefix(str: str):
        return Btc.PRIVATE_KEY_PREFIX_TESTNET[str]   
    
    def addDoubleSha256Checksum(hex: bytes) -> bytes:
        """Attaches the first 4 bytes of the double sha256 checksum of the hex bytes input to its end and returns the result as binary bytes"""

        hash2_hex = doubleSha256(hex)
        checksum = hash2_hex[:8]
        hex += checksum

        return codecs.decode(hex, 'hex')
        
    def uncompressPrivateKey(privkey_wif_compressed: str) -> str:

        privkey_bin = base58.b58decode(privkey_wif_compressed)
        privkey_hex = codecs.encode(privkey_bin, 'hex')

        privkey_hex = privkey_hex[:-8] # remove the checksum

        if privkey_hex.endswith(b"01"): # The private key indicates that the public key should get compressed 
            privkey_hex = privkey_hex[:-2]
            privkey_bin = Btc.addDoubleSha256Checksum(privkey_hex)

            # convert private_key into base58 encoded string
            privkey_wif_uncompressed = base58.b58encode(privkey_bin).decode('utf-8')
        
            return privkey_wif_uncompressed
        else: # the private key is already uncompressed
            return privkey_wif_compressed
        
    def compressPublicKey(pubkey: str) -> str:

        # check if the last byte is odd or even
        if (ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0):
            public_key_compressed = '02'
        else:
            public_key_compressed = '03'
            
        # add the 32 bytes of the x-coord
        public_key_compressed += pubkey[:64]

        return public_key_compressed

    def publicKeyPointToHex(pubkey: Point, compress: bool = True) -> str:
        x_hex = hex(pubkey.x)[2:] # remove 0x
        y_hex = hex(pubkey.y)[2:] # remove 0x

        while len(x_hex) < 64:
            x_hex = '0' + x_hex
        while len(y_hex) < 64:
            y_hex = '0' + y_hex

        pk_str = x_hex + y_hex

        if compress:
            pk_str = Btc.compressPublicKey(pk_str)
        else:
            pk_str = '04' + pk_str

        return pk_str

    def publicKeyPointToP2SH(public_key_point: Point):
        compressed_public_key = Btc.publicKeyPointToHex(public_key_point, True)

        key_hash = hash160(compressed_public_key)
        key_hash = hash160('0014' + key_hash)

        script_hash_hex = '05' + key_hash 
        script_hash_bin = Btc.addDoubleSha256Checksum(bytes(bytearray(script_hash_hex, 'ascii')))
        p2sh_address = base58.b58encode(script_hash_bin).decode('utf-8')

        return p2sh_address

        '''
        checksum = SHA256.new(SHA256.new(bytes.fromhex(script_hash)).digest()).hexdigest()[:8]
        p2sh_address = base58.b58encode(bytes.fromhex(script_hash + checksum))
        '''


        '''
        from bech32 import bech32_encode, convertbits

        # Get Bech32 address
        witness_program = bytes([0x00, 0x14]) + hash160.digest()
        bech32_address = bech32_encode('bc', convertbits(witness_program, 8, 5))
        '''

    def publicKeyPointToWif(pubkey: Point, compress: bool = True, for_testnet: bool = False) -> str:
        pk_str = Btc.publicKeyPointToHex(pubkey, compress)
        
        key_hash = hash160(pk_str)

        network_version_byte = '6f' if for_testnet else '00'
        modified_key_hash = network_version_byte + key_hash

        byte_25_address = Btc.addDoubleSha256Checksum(bytes(bytearray(modified_key_hash, 'ascii')))

        address = base58.b58encode(byte_25_address).decode('utf-8')

        return address

    def uncompressPublicKey(pubkey: str) -> str:
        if pubkey[:2] == '04': # the public key is already uncompressed
            return pubkey
        
        pk = bytearray.fromhex(pubkey)

        p = secp.p
        
        x = int.from_bytes(pk[1:33], byteorder='big')
        
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)

        if y % 2 != pk[0] % 2:
            y = p - y
        
        y = y.to_bytes(32, byteorder='big')

        return codecs.encode(b'\x04' + pk[1:33] + y, 'hex').decode('utf-8')

    def publicKeyHexToPoint(pubkey_hex: str) -> Point:
        pk = Btc.uncompressPublicKey(pubkey_hex);
        pk = pk[2:] # remove the 04 uncompressed identifier

        return Point(int('0x' + pk[:64], 16), int('0x' + pk[64:], 16))

    def privateHexKeyToWif(privkey_hex: str, compress: bool = True, for_testnet: bool = False) -> str:
        variant = Btc._getPrivateKeyPrefix(for_testnet)
        
        privkey_hex = variant + privkey_hex
        
        if compress: privkey_hex += '01'

        privkey_bytes = bytes(bytearray(privkey_hex, 'ascii'))

        privkey_bin = Btc.addDoubleSha256Checksum(privkey_bytes)
        privkey_wif = base58.b58encode(privkey_bin).decode('utf-8')

        return privkey_wif
    
    def generatePrivateHexKey(for_testnet: bool = None, use_entropy: bool = False):

        if use_entropy:
            bytes = ''
            seed = 42
            
            entropy = input('Type in some random chars: ')          
            entropy += urandom(1).hex()  

            entropy_len = len(entropy)
            for i in range(32):
                char = entropy[i % entropy_len]

                seed += ord(char)
                random.seed(seed)

                intval = random.randint(0, 255);
                hexval = hex(intval)[2:] # remove 0x
                if len(hexval) == 1:
                    hexval = '0' + hexval

                bytes += hexval
            
            if len(bytes) != 64:
                raise Exception('random byte count mismatch')
        else:
            bytes = urandom(32).hex()   

        if for_testnet != None:
            bytes = Btc._getPrivateKeyPrefix(for_testnet) + bytes     

        return bytes

    def privateWifKeyToHex(privkey_wif: str) -> str:

        privkey_wif_uncompressed = Btc.uncompressPrivateKey(privkey_wif)

        privkey_hex = codecs.encode(base58.b58decode(privkey_wif_uncompressed), 'hex')
        privkey_hex_str = codecs.decode(privkey_hex) # byte literal to string

        network_id_prefix = privkey_hex_str[:2]
        for_testnet = Btc._isTestNetKeyPrefix(network_id_prefix)
        privkey_hex_str = privkey_hex_str[2:-8] # remove net identifier and checksum  

        return for_testnet, privkey_hex_str 

    def privateKeyToPublicKeyWif(privkey: str) -> str:
        for_testnet = False

        if len(privkey) == 66: # hex key with network identifier
            network_id_prefix = privkey[:2]
            for_testnet = Btc._isTestNetKeyPrefix(network_id_prefix)
            privkey = privkey[2:]
  
        if len(privkey) != 64: # 64 chars is hex
            for_testnet, privkey = Btc.privateWifKeyToHex(privkey)

        privkey_int = int(privkey, 16)

        pk_point = secp.mult(privkey_int, secp.g) # or use: ecdsa.SigningKey.from_string(privkey_bin, curve=ecdsa.SECP256k1).verifying_key

        #print("\nCoords of the public key:", pk_point)
    
        pubkey_address_compressed = Btc.publicKeyPointToWif(pk_point, True, for_testnet) 
        pubkey_address_uncompressed = Btc.publicKeyPointToWif(pk_point, False, for_testnet) 


        print('P2SH', Btc.publicKeyPointToP2SH(pk_point))
        
        return (pubkey_address_compressed, pubkey_address_uncompressed)

    def wifToHash160(wif: str) -> str:

        address_bin = base58.b58decode(wif)
        hash_hex = codecs.encode(address_bin, 'hex')
        hash160 = codecs.decode(hash_hex[2:42])

        return hash160

####################################################################################

if __name__ == '__main__':
    #'''
    private_hex_key = '7e0dd9f1fb3c11c0b7b555b7f9115d63361283b4073472fa4055f2d765344113' # without network identifier
    print(Btc.privateKeyToPublicKeyWif(private_hex_key))
    exit()

    private_wif_key = Btc.privateHexKeyToWif(private_hex_key)
    print(Btc.privateKeyToPublicKeyWif(private_wif_key))

    print(Btc.privateKeyToPublicKeyWif('L2BYcYFgqjBtWASZyC7oScc7tdtBytZXvF6NGzmTRUupMiCMCrpC'))
    print(Btc.privateKeyToPublicKeyWif('5KhW6aAcyTjTvzvVSgnkd1P1q2BLWXg1jtK1U124sknzxNTbxHm'))
        
    print(Btc.wifToHash160('n2ozAmaunMGwPDjtxmZsyxDRjYAJqmZ6Dk')) 
    #'''
    priv_key = Btc.generatePrivateHexKey()
    print(priv_key)
    print(Btc.privateKeyToPublicKeyWif(priv_key))