from lib.secp256k1 import sign, scalar_mult, curve, verify_signature

'''
k = 0x75bcd15 # nonce
z = 0xa6b4103f527dfe43dfbadf530c247bac8a98b7463c7c6ad38eed97021d18ffcb # hash256(msg)
d = 0xf94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6 # privkey

rs = sign(z, d, k)
print(rs)

public_key = scalar_mult(d, curve.g)

print(verify_signature(public_key, z, rs))
'''

z = 47532434785953132308955062292737313655925535765828397397295369871553194000208
d = 0x514321CFA3C255BE2CE8249A70267B9D2935B7DC5B36055BA158D5F00C645F83
r = 110017519504628183300333744322457295885596324521473257357546331836191192852628
s = 13214572062096395104537544597126968537939503585960152346840461241014071165310

public_key = scalar_mult(d, curve.g)
p = bytearray.fromhex('02EE04998F8DBD9819D0391A5AA38DB1331B0274F64ABC3BC66D69EE61DB913459')
from lib.btc import decompress_pubkey

import binascii
pk = binascii.hexlify(decompress_pubkey(p)).decode('utf-8')
pk = pk[2:] # remove the 04 uncompressed identifier
p2 = (int('0x' + pk[:64], 16), int('0x' + pk[64:], 16))

print(p2)
print(f'{public_key=}')

#print(verify_signature(public_key, z, (r, s)))