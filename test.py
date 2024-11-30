from lib.secp256k1 import secp

z = 47532434785953132308955062292737313655925535765828397397295369871553194000208
private_key = 0x514321CFA3C255BE2CE8249A70267B9D2935B7DC5B36055BA158D5F00C645F83
k = 0x75bcd15 # nonce

rs = secp.sign(z, private_key, k)
public_key = secp.mult(private_key, secp.g)

print('Is signature correct:', secp.verifySignature(public_key, z, rs))

pubkey_hex = '02EE04998F8DBD9819D0391A5AA38DB1331B0274F64ABC3BC66D69EE61DB913459'
from lib.btc import publicKeyHexToSecpPoint
pubkey_point = publicKeyHexToSecpPoint(pubkey_hex);

print(pubkey_point == public_key)