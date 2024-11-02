from lib.btc import privateHexKeyToWif, privateKeyToPublicKeyWif, wifToHash160

#print(privateHexKeyToWif('7e0dd9f1fb3c11c0b7b555b7f9115d63361283b4073472fa4055f2d765344113'))
#print(wifToHash160('n2ozAmaunMGwPDjtxmZsyxDRjYAJqmZ6Dk'))

k = int('75bcd15', 16) # nonce
z = int('a6b4103f527dfe43dfbadf530c247bac8a98b7463c7c6ad38eed97021d18ffcb', 16) # hash256(msg)
d = int('f94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6', 16) # privkey

from lib.secp256k1 import sign

rs = sign(z, d, k)
print(rs)