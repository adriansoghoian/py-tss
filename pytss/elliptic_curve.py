from collections import namedtuple
from dataclasses import dataclass
from pytss.common_crypto import (
    gen_random_int
)

@dataclass
class PrimeGaloisField:
    prime: int

    def __contains__(self, field_element: "FieldElement") -> bool:
        return 0 <= field_element.value < self.prime

@dataclass
class FieldElement:
    value: int
    field: PrimeGaloisField

    def __repr__(self):
        return '0x' + f'{self.value}'.zfill(64)
        
    @property
    def P(self) -> int:
        return self.field.prime
    
    def __add__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value + other.value) % self.P,
            field=self.field
        )
    
    def __sub__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value - other.value) % self.P,
            field=self.field
        )

    def __rmul__(self, scalar: int) -> "FieldElement":
        return FieldElement(
            value=(self.value * scalar) % self.P,
            field=self.field
        )

    def __mul__(self, other: "FieldElement") -> "FieldElement":
        return FieldElement(
            value=(self.value * other.value) % self.P,
            field=self.field
        )
        
    def __pow__(self, exponent: int) -> "FieldElement":
        return FieldElement(
            value=pow(self.value, exponent, self.P),
            field=self.field
        )

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
        if not isinstance(self.a, FieldElement):
            self.a = FieldElement(self.a, self.field)

        if not isinstance(self.b, FieldElement):
            self.b = FieldElement(self.b, self.field)
    
        if self.a not in self.field or self.b not in self.field:
            raise ValueError

@dataclass
class Point:
    x: int
    y: int

    curve: EllipticCurve

    def __post_init__(self):
        if self.x is None and self.y is None:
            return

        if not isinstance(self.x, FieldElement):
            self.x = FieldElement(self.x, self.curve.field)
        
        if not isinstance(self.y, FieldElement):
            self.y = FieldElement(self.y, self.curve.field)

        if self not in self.curve:
            raise ValueError

    def __add__(self, other):
        I = infinity_point(self.curve)
        if self == I:
            return other

        if other == I:
            return self

        if self.x == other.x and self.y == (-1 * other.y):
            return I

        if self.x != other.x:
            x1, x2 = self.x, other.x
            y1, y2 = self.y, other.y

            s = (y2 - y1) / (x2 - x1)
            x3 = s ** 2 - x1 - x2
            y3 = s * (x1 - x3) - y1

            return self.__class__(
                x=x3.value,
                y=y3.value,
                curve=self.curve
            )

        if self == other and self.y is None:
            return I

        if self == other:
            x1, y1, a = self.x, self.y, self.curve.a

            s = (3 * x1 ** 2 + a) / (2 * y1)
            x3 = s ** 2 - 2 * x1
            y3 = s * (x1 - x3) - y1

            return self.__class__(
                x=x3.value,
                y=y3.value,
                curve=self.curve
            )

    def __rmul__(self, scalar: int) -> "Point":
        current = self
        result = infinity_point(self.curve)
        while scalar:
            if scalar & 1: 
                result = result + current
            current = current + current
            scalar >>= 1
        return result

@dataclass
class Signature:
    r: int
    s: int
    G: Point
    N: int

    def verify(self, z: int, pub_key: Point) -> bool:
        s_inv = pow(self.s, -1, self.N)
        u = (z * s_inv) % self.N
        v = (self.r * s_inv) % self.N
        
        return (u*self.G + v*pub_key).x.value == self.r

@dataclass
class PrivateKey:
    secret: int
    G: Point
    N: int
    
    def sign(self, z: int) -> Signature:
        e = self.secret
        k = gen_random_int(0, self.N)
        R = k * self.G
        r = R.x.value
        k_inv = pow(k, -1, self.N) 
        s = ((z + r*e) * k_inv) % self.N
        
        return Signature(r, s, self.G, self.N)

def infinity_point(curve: EllipticCurve) -> Point:
    return Point(None, None, curve)

secp256k1 = EllipticCurve(
    a=FieldElement(value=0, field=PrimeGaloisField(prime=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)),
    b=FieldElement(value=7, field=PrimeGaloisField(prime=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)),
    field=PrimeGaloisField(prime=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
)

secp256k1_generator = Point(
    x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    curve=secp256k1
)

secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
