# ECDSA-SECP256K1 code from: https://gist.github.com/onyb/cf795c819fdf8aa6015de2772fde24de

from dataclasses import dataclass
from random import randint
from hashlib import sha256
import sha3


@dataclass
class PrimeGaloisField:
    prime: int

    def __contains__(self, field_value: "FieldElement") -> bool:
        # called whenever you do: <FieldElement> in <PrimeGaloisField>
        return 0 <= field_value.value < self.prime


@dataclass
class FieldElement:
    value: int
    field: PrimeGaloisField

    def __repr__(self):
        return "0x" + f"{self.value:x}".zfill(64)

    @property
    def P(self) -> int:
        return self.field.prime

    def __add__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(value=(self.value + other.value) % self.P, field=self.field)

    def __sub__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(value=(self.value - other.value) % self.P, field=self.field)

    def __rmul__(self, scalar: int) -> "FieldValue":
        return FieldElement(value=(self.value * scalar) % self.P, field=self.field)

    def __mul__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(value=(self.value * other.value) % self.P, field=self.field)

    def __pow__(self, exponent: int) -> "FieldElement":
        return FieldElement(value=pow(self.value, exponent, self.P), field=self.field)

    def __truediv__(self, other: "FieldElement") -> "FieldElement":
        other_inv = other ** -1
        return self * other_inv


@dataclass
class EllipticCurve:
    a: int
    b: int

    field: PrimeGaloisField

    def __contains__(self, point: "Point") -> bool:
        x, y = point.x, point.y
        return y ** 2 == x ** 3 + self.a * x + self.b

    def __post_init__(self):
        # Encapsulate int parameters in FieldElement
        self.a = FieldElement(self.a, self.field)
        self.b = FieldElement(self.b, self.field)

        # Check for membership of curve parameters in the field.
        if self.a not in self.field or self.b not in self.field:
            raise ValueError


# Ref: https://en.bitcoin.it/wiki/Secp256k1
# secp256k1 elliptic curve equation: y² = x³ + 7

# Prime of the finite field
P: int = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
field = PrimeGaloisField(prime=P)

# Elliptic curve parameters A and B of the curve : y² = x³ Ax + B
A: int = 0
B: int = 7

secp256k1 = EllipticCurve(a=A, b=B, field=field)


inf = float("inf")


@dataclass
class Point:
    x: int
    y: int

    curve: EllipticCurve

    def __post_init__(self):
        # Ignore validation for I
        if self.x is None and self.y is None:
            return

        # Encapsulate int coordinates in FieldElement
        self.x = FieldElement(self.x, self.curve.field)
        self.y = FieldElement(self.y, self.curve.field)

        # Verify if the point satisfies the curve equation
        if self not in self.curve:
            raise ValueError

    def __add__(self, other):
        #################################################################
        # Point Addition for P₁ or P₂ = I   (identity)                  #
        #                                                               #
        # Formula:                                                      #
        #     P + I = P                                                 #
        #     I + P = P                                                 #
        #################################################################
        if self == I:
            return other

        if other == I:
            return self

        #################################################################
        # Point Addition for X₁ = X₂   (additive inverse)               #
        #                                                               #
        # Formula:                                                      #
        #     P + (-P) = I                                              #
        #     (-P) + P = I                                              #
        #################################################################
        if self.x == other.x and self.y == (-1 * other.y):
            return I

        #################################################################
        # Point Addition for X₁ ≠ X₂   (line with slope)                #
        #                                                               #
        # Formula:                                                      #
        #     S = (Y₂ - Y₁) / (X₂ - X₁)                                 #
        #     X₃ = S² - X₁ - X₂                                         #
        #     Y₃ = S(X₁ - X₃) - Y₁                                      #
        #################################################################
        if self.x != other.x:
            x1, x2 = self.x, other.x
            y1, y2 = self.y, other.y

            s = (y2 - y1) / (x2 - x1)
            x3 = s ** 2 - x1 - x2
            y3 = s * (x1 - x3) - y1

            return self.__class__(x=x3.value, y=y3.value, curve=secp256k1)

        #################################################################
        # Point Addition for P₁ = P₂   (vertical tangent)               #
        #                                                               #
        # Formula:                                                      #
        #     S = ∞                                                     #
        #     (X₃, Y₃) = I                                              #
        #################################################################
        if self == other and self.y == inf:
            return I

        #################################################################
        # Point Addition for P₁ = P₂   (tangent with slope)             #
        #                                                               #
        # Formula:                                                      #
        #     S = (3X₁² + a) / 2Y₁         .. ∂(Y²) = ∂(X² + aX + b)    #
        #     X₃ = S² - 2X₁                                             #
        #     Y₃ = S(X₁ - X₃) - Y₁                                      #
        #################################################################
        if self == other:
            x1, y1, a = self.x, self.y, self.curve.a

            s = (3 * x1 ** 2 + a) / (2 * y1)
            x3 = s ** 2 - 2 * x1
            y3 = s * (x1 - x3) - y1

            return self.__class__(x=x3.value, y=y3.value, curve=secp256k1)

    def __rmul__(self, scalar: int) -> "Point":
        # Naive approach:
        #
        # result = I
        # for _ in range(scalar):  # or range(scalar % N)
        #     result = result + self
        # return result

        # Optimized approach using binary expansion
        current = self
        result = I
        while scalar:
            if scalar & 1:  # same as scalar % 2
                result = result + current
            current = current + current  # point doubling
            scalar >>= 1  # same as scalar / 2
        return result


# Generator point of the abelian group used in Bitcoin
G = Point(
    x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    curve=secp256k1,
)

# Order of the group generated by G, such that nG = I
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

I = Point(x=None, y=None, curve=secp256k1)


@dataclass
class PrivateKey:
    secret: int

    def sign(self, z: int) -> "Signature":
        e = self.secret
        k = randint(0, N)
        R = k * G
        r = R.x.value
        k_inv = pow(k, -1, N)  # Python 3.8+
        s = ((z + r * e) * k_inv) % N

        return Signature(r, s)


@dataclass
class Signature:
    r: int
    s: int

    def verify(self, z: int, pub_key: Point) -> bool:
        s_inv = pow(self.s, -1, N)  # Python 3.8+
        u = (z * s_inv) % N
        v = (self.r * s_inv) % N

        return (u * G + v * pub_key).x.value == self.r

def pubkey_to_str(pubkey):
    return pubkey.x.value.to_bytes(32, "big").hex() + pubkey.y.value.to_bytes(32, "big").hex()


def generate_key():
    priv = PrivateKey(randint(0, N))
    print("privkey: ", hex(priv.secret))

    pub = priv.secret * G
    pubkeystr = pub.x.value.to_bytes(32, "big").hex() + pub.y.value.to_bytes(32, "big").hex()
    print("pubkey: ", pubkeystr)

    pubkeybytes = bytes.fromhex(pubkeystr)
    keccaked_public_key = sha3.keccak_256()
    keccaked_public_key.update(pubkeybytes)
    address = "0x" + keccaked_public_key.hexdigest()[24:]
    print(address)


PRIV1 = "8b0a79fb51e77dd65ae5c36733f0bbcc14d189c11a114ad24f02d52adf4d9f8e"
PUB1 = "d8216e2a7d59928e9dc830153c1a95eae5aff22f3d71aee4f3b0286e191db863353ddd2f722291fa3d4acc67deec756be240685f8dc8b87c25a43a36dd4aa54d"
ADDR1 = "0xc87f9fc3544eaa19bd4e43c55f84318f45094209"
PRIV2 = "9fc894a4780f03be0aba1628144ffadc53ad37992793be8b11544ddd12242331"
PUB2 = "3d61f24fce062ab8c2c3f754283c73afa57cbd5d1fcc5365c696c41806a535f05329aef2fbc03b423fea22c3474bd265ba3b67935c017e26c1387935d4251b71"
ADDR2 = "0x33db9c6743a1a9f0065fc6a6fdfade58f23dc056"
PRIV3 = "7b9127fa28d77dcc06614f6b5d81e67188ffe4a728fbc8b5530a3607c67a102b"
PUB3 = "705e8b898ed018111651a0d9aaf5b66486dcfb5b76afbbc546bdb39608263c7ecd713caa56f3c1c2e0330f61206c6baa3ec43b5e8567e144cd0732e4ec34f547"
ADDR3 = "0x19aba90dbffca8d016040514b6fd64597b171850"

def elliptic_curve_test():
    # pubkeystr = "a7354ba6e1ff9ccdc480e86b5bdbb7b626cf809da86e9f4a1b648df77c3e1bebdc701843d7ccb9917431fab88ec01789582f65a06b8cbeb169efb7d2354831ed"
    # pubkey = bytes.fromhex(pubkeystr)

    # keccaked_public_key = sha3.keccak_256()
    # keccaked_public_key.update(pubkey)
    # address = "0x" + keccaked_public_key.hexdigest()[24:]
    # print(address)

    # e = PrivateKey(randint(0, N))  # generate a private key
    # pub = e.secret * G  # public point corresponding to e
    # z = randint(0, 2 ** 256)  # generate a random message for testing
    # signature: Signature = e.sign(z)
    # print(signature)

    # priv1 = PrivateKey(randint(0, N))
    # pub1 = priv1.secret * G

    # priv2 = PrivateKey(randint(0, N))
    # pub2 = priv2.secret * G
    # print(pub1)

    generate_key()
    # secret = int(PRIV1, 16)

def revoke_vote_test():
    contract_addr = "70D1419b54d7d657240a04d87dc4121c294d12cb"
    contract_addr = contract_addr.lower()
    enclave_hash = "2b293a7b5cffc0cd9001e423645e280dce6c7350123e57c8de733738d9851b67"
    msg = contract_addr + enclave_hash
    print("message", msg)
    hashedMsg = sha256(bytes.fromhex(msg)).hexdigest()
    print("hashed message: ", "0x"+ hashedMsg)
    msg_int = int(hashedMsg, 16)

    priv3 = PrivateKey(int(PRIV3, 16))
    signature = priv3.sign(msg_int)
    # print(signature.r.to_bytes(32, "big").hex(), signature.s.to_bytes(32, "big").hex())
    print("0x" + signature.r.to_bytes(32, "big").hex())
    print("0x" + signature.s.to_bytes(32, "big").hex())


if __name__ == "__main__":
    # elliptic_curve_test()
    revoke_vote_test()
