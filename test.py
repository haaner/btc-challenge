from lib.btc import Btc 

pubkey_hex = '02EE04998F8DBD9819D0391A5AA38DB1331B0274F64ABC3BC66D69EE61DB913459'
pubkey_point = Btc.publicKeyHexToPoint(pubkey_hex);