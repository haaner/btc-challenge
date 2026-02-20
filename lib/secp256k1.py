from random import randrange

if __package__:
    from os import sys, path
    sys.path.append(path.dirname(path.abspath(__file__)))

from aux import inverseMod

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):   
        return self.x == other.x and self.y == other.y

    def __str__(self):
        return f'{{ {self.x=}, {self.y=} }}'
    
    def __repr__(self):
        return str(self)       
    
class EllipticCurve:
    def __init__(self, p: int, a: int, b: int, g: Point, n: int):
        self.p = p #: Field characteristic

        self.a = a #: Curve coefficient
        self.b = b #: Curve coefficient     

        self.g = g 
        '''Group base / generator point'''
        self.n = n 
        '''Group order'''

    def contains(self, point: Point) -> bool:
        """Returns True if the given point lies on the elliptic curve."""
        if point is None:
            # None represents the point at infinity.
            return True

        x, y = point.x, point.y

        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def add(self, point1: Point, point2: Point) -> Point:
        """Returns the result of point1 + point2 according to the group law."""
        assert self.contains(point1)
        assert self.contains(point2)

        if point1 is None:
            # 0 + point2 = point2
            return point2
        if point2 is None:
            # point1 + 0 = point1
            return point1

        x1, y1 = point1.x, point1.y
        x2, y2 = point2.x, point2.y

        if x1 == x2 and y1 != y2:
            # point1 + (-point1) = 0
            return None

        if x1 == x2:
            # This is the case point1 == point2.
            m = (3 * x1 * x1 + self.a) * inverseMod(2 * y1, self.p)
        else:
            # This is the case point1 != point2.
            m = (y1 - y2) * inverseMod(x1 - x2, self.p)

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)

        result = Point(x3 % self.p, -y3 % self.p)

        assert self.contains(result)

        return result

    def negatePoint(self, point: Point) -> Point:
        return Point(point.x, self.n - point.y)

    def mult(self, k: int, point: Point) -> Point:
        """Returns k * point computed using the double and point_add algorithm."""
        assert self.contains(point)

        if k % self.n == 0 or point is None:
            return None

        if k < 0:
            # k * point = -k * (-point)
            return self.mult(-k, self.negatePoint(point))

        result = None
        addend = point

        while k:
            if k & 1: # Add.
                result = self.add(result, addend)

            # Double.
            addend = self.add(addend, addend)

            k >>= 1

        assert self.contains(result)

        return result

    def sign(self, z: int, private_key: int, k2: int = None) -> list[list[int], bool]:

        while True:

            if k2 == None:
                k = randrange(1, self.n)    
            else:
                k = k2

            P = self.mult(k, self.g)

            r = P.x % self.n
            s = ((z + r * private_key) * inverseMod(k, self.n)) % self.n

            if (r and s) or k2 != None:
                break

        corrected = s > self.n/2
        if corrected:
            s = self.n - s

        return ((r, s), corrected)
    
    def verifySignature(self, public_key: Point, z: int, r_s: tuple[int, int]) -> bool:

        r, s = r_s

        w = inverseMod(s, self.n)
        u1 = (z * w) % self.n
        u2 = (r * w) % self.n

        P = self.add(self.mult(u1, self.g), self.mult(u2, public_key))

        return (r % self.n) == (P.x % self.n)
               
class Secp256k1(EllipticCurve):
    def __init__(self):
        super().__init__(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, # == 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
                         0, 7, 
                         Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
                         0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)
      
secp = Secp256k1()
      
if __name__ == '__main__':

    print("Basepoint:\t", secp.g)

    a = randrange(1, secp.n)
    print("\nAlice\'s secret key:\t", a)
    
    aG = secp.mult(a, secp.g)
    print("Alice\'s public key:\t", aG)
    
    b = randrange(1, secp.n)
    print("\nBob\'s secret key:\t", b)
    
    bG = secp.mult(b, secp.g)
    print("Bob\'s public key:\t", bG)
    
    abG = secp.mult(b, aG)
    baG = secp.mult(a, bG)
    
    print('\nMultiplication is commutative:', abG == baG)

    a_inv = inverseMod(a, secp.n)
    bG_recover = secp.mult(a_inv, abG)
  
    print("\na_inv abG:\t\t", bG_recover)

    if bG == bG_recover: print("\nKey recovered")

    ###
    
    z = 47532434785953132308955062292737313655925535765828397397295369871553194000208
    private_key = 0x514321CFA3C255BE2CE8249A70267B9D2935B7DC5B36055BA158D5F00C645F83
    k = 0x75bcd15 # nonce

    rs, corrected = secp.sign(z, private_key, k)
    public_key = secp.mult(private_key, secp.g)

    print('Is signature correct:', secp.verifySignature(public_key, z, rs))