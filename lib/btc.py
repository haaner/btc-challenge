import base58
import codecs
import hashlib

'''
if __package__:
    from .secp256k1 import curve, scalar_mult
else:
    from secp256k1 import curve, scalar_mult
'''

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

def hash160(hex: bytes) -> bytes:
    """Returns the hex input hash160'ed hex bytes"""

    bin = codecs.decode(hex, 'hex')

    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()

    return codecs.encode(hash2, 'hex')

from secp256k1 import secp, Point

class Btc:
    
    def addHash160Checksum(hex: bytes) -> bytes:
        """Attaches the first 4 bytes of the hash160 checksum of the hex bytes input to its end and returns the result as binary bytes"""

        hash2_hex = hash160(hex)
        checksum = hash2_hex[:8]
        hex += checksum

        return codecs.decode(hex, 'hex')
        
    def uncompressPrivateKey(privkey_wif_compressed: str) -> str:

        privkey_bin = base58.b58decode(privkey_wif_compressed)
        privkey_hex = codecs.encode(privkey_bin, 'hex')

        privkey_hex = privkey_hex[:-8] # remove the checksum

        if privkey_hex.endswith(b"01"): # The private key indicates that the public key should get compressed 
            privkey_hex = privkey_hex[:-2]
            privkey_bin = Btc.addHash160Checksum(privkey_hex)

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

    def publicKeyPointToWif(pubkey: Point, compress: bool = True) -> str:

        x_hex = hex(pubkey.x)[2:] # remove 0x
        y_hex = hex(pubkey.y)[2:] # remove 0x

        pk_str = x_hex + y_hex

        if compress:
            pk_str = '04' + pk_str
        else:
            pk_str = Btc.compressPublicKey(pk_str)

        # Converting to binary for SHA-256 hashing
        pubkey_bin = codecs.decode(pk_str, 'hex')

        sha = hashlib.sha256(pubkey_bin)

        rip = hashlib.new('ripemd160')
        rip.update(sha.digest())
        key_hash = rip.hexdigest()

        modified_key_hash = "00" + key_hash # 00 for main net

        byte_25_address = Btc.addHash160Checksum(bytes(bytearray(modified_key_hash, 'ascii')))

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

    def publicKeyHexToSecpPoint(pubkey_hex: str) -> Point:

        pk = Btc.uncompressPublicKey(pubkey_hex);
    
        pk = pk[2:] # remove the 04 uncompressed identifier

        return Point(int('0x' + pk[:64], 16), int('0x' + pk[64:], 16))

    def privateHexKeyToWif(privkey_hex: str, compress: bool = True, mainnet = True) -> str:

        if mainnet: variant = '80' 
        else: variant = 'ef'
        
        privkey_hex = variant + privkey_hex
        
        if compress: privkey_hex += '01'

        privkey_bytes = bytes(bytearray(privkey_hex, 'ascii'))

        privkey_bin = Btc.addHash160Checksum(privkey_bytes)
        privkey_wif = base58.b58encode(privkey_bin).decode('utf-8')

        return privkey_wif

    def privateWifKeyToHex(privkey_wif: str) -> str:

        privkey_wif_uncompressed = Btc.uncompressPrivateKey(privkey_wif)

        privkey_hex = codecs.encode(base58.b58decode(privkey_wif_uncompressed), 'hex')
        privkey_hex = privkey_hex[2:-8] # remove net identifier and checksum  
    
        return codecs.decode(privkey_hex) # byte literal to string

    def privateKeyToPublicKeyWif(privkey: str) -> str:

        if len(privkey) != 64: # 64 chars is hex
            privkey = Btc.privateWifKeyToHex(privkey)

        privkey_int = int(privkey, 16)

        pk_point = secp.mult(privkey_int, secp.g) # or use: ecdsa.SigningKey.from_string(privkey_bin, curve=ecdsa.SECP256k1).verifying_key

        #print("\nCoords of the public key:", pk_point)
    
        pubkey_address_compressed = Btc.publicKeyPointToWif(pk_point) 
        pubkey_address_uncompressed = Btc.publicKeyPointToWif(pk_point, False) 
        
        return (pubkey_address_compressed, pubkey_address_uncompressed)

    def wifToHash160(wif: str) -> str:

        address_bin = base58.b58decode(wif)
        hash_hex = codecs.encode(address_bin, 'hex')
        hash160 = codecs.decode(hash_hex[2:42])

        return hash160

####################################################################################

if __name__ == '__main__':

    print(Btc.privateKeyToPublicKeyWif('7e0dd9f1fb3c11c0b7b555b7f9115d63361283b4073472fa4055f2d765344113'))
    print(Btc.privateKeyToPublicKeyWif('L2BYcYFgqjBtWASZyC7oScc7tdtBytZXvF6NGzmTRUupMiCMCrpC'))
    print(Btc.privateKeyToPublicKeyWif('5KhW6aAcyTjTvzvVSgnkd1P1q2BLWXg1jtK1U124sknzxNTbxHm'))
    
    print(Btc.privateHexKeyToWif('7e0dd9f1fb3c11c0b7b555b7f9115d63361283b4073472fa4055f2d765344113'))
    print(Btc.wifToHash160('n2ozAmaunMGwPDjtxmZsyxDRjYAJqmZ6Dk'))