import hashlib
import base58
import codecs

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

####################################################################################

#privkey = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
privkey = "L2BYcYFgqjBtWASZyC7oScc7tdtBytZXvF6NGzmTRUupMiCMCrpC"
#privkey = "5KhW6aAcyTjTvzvVSgnkd1P1q2BLWXg1jtK1U124sknzxNTbxHm"

if len(privkey) != 64: # 64 chars is hex
    privkey_wif_uncompressed = uncompress_privkey(privkey)

    if privkey != privkey_wif_uncompressed:
        print("privkey_wif_compressed='" + privkey)
    else:
        privkey_wif_uncompressed = privkey

    print(f"{privkey_wif_uncompressed=}")

    privkey_hex = codecs.encode(base58.b58decode(privkey_wif_uncompressed), 'hex')

    '''
    # Check if the key is mainnet or testnet
    if privkey_hex.startswith(b"80"):
        testnet = False
    elif privkey_hex.startswith(b"ef"):
        testnet = True
    '''
    privkey_hex = privkey_hex[2:-8] # remove net identifier and checksum  

    privkey = codecs.decode(privkey_hex) # byte literal to string

####

privkey_int = int(privkey, 16)

x, y = scalar_mult(privkey_int, curve.g) # or use: ecdsa.SigningKey.from_string(privkey_bin, curve=ecdsa.SECP256k1).verifying_key

#print("\nCoords of the public key:", (x, y))

x_hex = hex(x)[2:]
y_hex = hex(y)[2:] 

pubkey = x_hex + y_hex

pubkey_address_uncompressed = compute_pubkey_address('04' + pubkey) 
print(f"\n{pubkey_address_uncompressed=}")

pubkey_compressed = compress_pubkey(pubkey)
pubkey_address_compressed = compute_pubkey_address(pubkey_compressed)
print(f'{pubkey_address_compressed=}')