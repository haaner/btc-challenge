def inverseMod(k: int, p: int) -> int:
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if p == None:
        p = self.n

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverseMod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p

def hash160(hex: bytes) -> bytes:
    """Returns the hex input hash160'ed hex bytes"""

    import codecs
    import hashlib

    bin = codecs.decode(hex, 'hex')

    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()

    return codecs.encode(hash2, 'hex')

def parseVarint(varint: str) -> tuple[int, str]: 

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