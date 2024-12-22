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

def doubleSha256(hex: str) -> str:
    """Returns the hex'd doubleSha256 of the hex input string"""

    bin = codecs.decode(hex, 'hex')

    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()

    return codecs.encode(hash2, 'hex').decode()

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
    
    def addDoubleSha256Checksum(hex: str) -> bytes:
        """Attaches the first 4 bytes of the double sha256 checksum of the hex bytes input to its end and returns the result as binary bytes"""

        hash2_hex = doubleSha256(hex)
        checksum = hash2_hex[:8]
        hex += checksum

        return codecs.decode(hex, 'hex')
        
    def uncompressPrivateKey(privkey_wif_compressed: str) -> str:

        privkey_bin = base58.b58decode(privkey_wif_compressed)
        privkey_hex = codecs.encode(privkey_bin, 'hex').decode()

        privkey_hex = privkey_hex[:-8] # remove the checksum

        if privkey_hex.endswith('01'): # The private key indicates that the public key should get compressed 
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

    def publicKeyHexToPoint(pubkey_hex: str) -> Point:
        pk = Btc.uncompressPublicKey(pubkey_hex);
        pk = pk[2:] # remove the 04 uncompressed identifier

        return Point(int('0x' + pk[:64], 16), int('0x' + pk[64:], 16))
    
    def publicKeyPointToP2SH(public_key_point: Point, for_testnet: bool = False): 
        compressed_public_key = Btc.publicKeyPointToHex(public_key_point, True)
        key_hash = hash160(compressed_public_key)
        key_hash = hash160('0014' + key_hash)

        network_version_byte = 'c4' if for_testnet else '05'
        script_hash_hex = network_version_byte + key_hash 
        script_hash_bin = Btc.addDoubleSha256Checksum(script_hash_hex)
        p2sh_address = base58.b58encode(script_hash_bin).decode('utf-8')

        return p2sh_address
      
    def publicKeyPointToP2WPKH(public_key_point: Point, for_testnet: bool = False): 
        compressed_public_key = Btc.publicKeyPointToHex(public_key_point, True)
        key_hash = hash160(compressed_public_key)

        network_version_str = 'tb' if for_testnet else 'bc'

        from bech32 import encode
        return encode(network_version_str, 0x00, bytes.fromhex(key_hash))
   
    def publicKeyHexToP2WPKH(pubkey_hex: str, for_testnet: bool = False) -> str:
        return Btc.publicKeyPointToP2WPKH(Btc.publicKeyHexToPoint(pubkey_hex), True, for_testnet)
    
    def publicKeyPointToWif(pubkey: Point, compress: bool = True, for_testnet: bool = False) -> str:
        pk_str = Btc.publicKeyPointToHex(pubkey, compress)
        
        key_hash = hash160(pk_str)

        network_version_byte = '6f' if for_testnet else '00'
        modified_key_hash = network_version_byte + key_hash

        byte_25_address = Btc.addDoubleSha256Checksum(modified_key_hash)

        return base58.b58encode(byte_25_address).decode('utf-8')
 
    def publicKeyHexToWif(pubkey_hex: str, compress: bool = True, for_testnet: bool = False) -> str:
        return Btc.publicKeyPointToWif(Btc.publicKeyHexToPoint(pubkey_hex), compress, for_testnet)
    
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

    def publicKeyHexToHash160(pubkey_hex: str, compress = True, for_testnet: bool = False) -> str:
        return Btc.wifToHash160(Btc.publicKeyHexToWif(pubkey_hex, compress, for_testnet))

    def privateHexKeyToWif(privkey_hex: str, compress: bool = True, for_testnet: bool = False) -> str:
        variant = Btc._getPrivateKeyPrefix(for_testnet)
        
        privkey_hex = variant + privkey_hex
        
        if compress: privkey_hex += '01'

        privkey_bin = Btc.addDoubleSha256Checksum(privkey_hex)
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

    def privateKeyToPublicKeyAddresses(privkey: str) -> dict:
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

        return { 'P2PKH-C': pubkey_address_compressed, 'P2PKH-U': pubkey_address_uncompressed, 'P2SH': Btc.publicKeyPointToP2SH(pk_point, for_testnet), 'P2WPKH': Btc.publicKeyPointToP2WPKH(pk_point, for_testnet) }

    def wifToHash160(wif: str) -> str:
        address_bin = base58.b58decode(wif)
        hash_hex = codecs.encode(address_bin, 'hex')
        hash160 = codecs.decode(hash_hex[2:42])

        return hash160
    
    def bechToHash160(bech32_address: str) -> str:
        from bech32 import decode
        version, data = decode(bech32_address[:2], bech32_address)      

        return ''.join(format(x, '02x') for x in data)

####################################################################################

if __name__ == '__main__':
    
    for private_hex_key in [ 
        'efDBFF11E0F2F1AA5089465A591C5E523D1CA92668DED893155CDFABC94CC14E30', # ef -> testnet
        'ef26F85CE8B2C635AD92F6148E4443FE415F512F3F29F44AB0E2CBDA819295BBD5',
        'efD9172189D7700FDFB4B6A5C4A83990EAEAFE455441B7D43FF85678EB93AC2713',
        'L2BYcYFgqjBtWASZyC7oScc7tdtBytZXvF6NGzmTRUupMiCMCrpC',
        '5KhW6aAcyTjTvzvVSgnkd1P1q2BLWXg1jtK1U124sknzxNTbxHm'
    ]:
        print(Btc.privateKeyToPublicKeyAddresses(private_hex_key))

    print()
      
    if Btc.bechToHash160('bc1qpdnwhl8zfjpy5jfm2zssjqrdpje83ntgl5j00c') != Btc.wifToHash160('123HjFA4jzEJY6t46A4otSTgZLUVv5vp7g'):
        print("The wif / bech hashes mismatch!") 

    priv_key = Btc.generatePrivateHexKey()
    test_priv_key = 'ef' + priv_key
    main_priv_key = '80' + priv_key
    
    print(Btc.privateKeyToPublicKeyAddresses(test_priv_key))
    print(Btc.privateKeyToPublicKeyAddresses(main_priv_key))
    print(Btc.privateKeyToPublicKeyAddresses(priv_key))

    if Btc.wifToHash160('n2ozAmaunMGwPDjtxmZsyxDRjYAJqmZ6Dk') != 'e993470936b573678dc3b997e56db2f9983cb0b4':
        print("The wif hash is incorrect!") 

    if Btc.publicKeyHexToHash160('02AE68D299CBB8AB99BF24C9AF79A7B13D28AC8CD21F6F7F750300EDA41A589A5D', True, True) != '6a721dcca372f3c17b2c649b2ba61aa0fda98a91':
        print("The pkh hash is incorrect!") 

    print()

    print(Btc.wifToHash160('18p3G8gQ3oKy4U9EqnWs7UZswdqAMhE3r8'))
    print(Btc.publicKeyHexToHash160('03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31', True, False))
    print(Btc.publicKeyHexToWif('03f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31', True, False))   