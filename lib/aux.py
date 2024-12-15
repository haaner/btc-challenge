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

def reverseHexBytes(hex: str) -> str:
    return int('0x' + hex, 16).to_bytes(len(hex) // 2, byteorder='little').hex()

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

        byteval = varint[:count]

        intval = int.from_bytes(bytes.fromhex(byteval), byteorder='little')
        varint = varint[count:]
        
    return (intval, varint)

def toVarint(i: int) -> str:
    
    if i <= 252:
        byte_length = 1
        prefix = ''
    elif i <= 65535:
        byte_length = 2
        prefix = 'fd'
    elif i <= 4294967295:
        byte_length = 4
        prefix = 'fe'
    elif i <= 18446744073709551615:
        byte_length = 8
        prefix = 'ff'
    else:
        raise ValueError("Integer is out of range")

    # Konvertiere die Zahl in Bytes und kehre die Byte-Reihenfolge um
    byte_array = i.to_bytes(byte_length, byteorder='little')
    hex_string = prefix + byte_array.hex()

    return hex_string

if __name__ == '__main__':

    print(parseVarint('fe59cd1e21affe'))
    print(toVarint(555666777))

    print(parseVarint('04affe'))
    print(toVarint(4))
