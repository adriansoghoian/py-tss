import unittest
from pytss.elliptic_curve import (
    EllipticCurve,
    FieldElement,
    PrimeGaloisField,
    Point,
    Signature,
    PrivateKey,
    secp256k1
)
from pytss.common_crypto import (
    gen_random_int
)
from pytss.utils import (
    int_to_hex_str
)

G = Point(
    x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    curve=secp256k1
)

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

I = Point(x=None, y=None, curve=secp256k1) 

class TestEllipticCurve(unittest.TestCase):

    def test_btc_elliptic_curve(self):
        # # Test case 1
        self.assertTrue(N * G == I)

        # Test case 2
        pub = Point(
            x=0x9577FF57C8234558F293DF502CA4F09CBC65A6572C842B39B366F21717945116,
            y=0x10B49C67FA9365AD7B90DAB070BE339A1DAF9052373EC30FFAE4F72D5E66D053,
            curve=secp256k1
        )
        e: int = 2 ** 240 + 2 ** 31
        self.assertTrue(e * G == pub)

    def test_ecdsa(self):
        pub = Point(
            x=0x887387E452B8EACC4ACFDE10D9AAF7F6D9A0F975AABB10D006E4DA568744D06C,
            y=0x61DE6D95231CD89026E286DF3B6AE4A894A3378E393E93A0F45B666329A0AE34,
            curve=secp256k1
        )

        z = 0xEC208BAA0FC1C19F708A9CA96FDEFF3AC3F230BB4A7BA4AEDE4942AD003C0F60
        r = 0xAC8D1C87E51D0D441BE8B3DD5B05C8795B48875DFFE00B7FFCFAC23010D3A395
        s = 0x68342CEFF8935EDEDD102DD876FFD6BA72D6A427A3EDB13D26EB0781CB423C4

        self.assertTrue(Signature(r, s, G, N).verify(z, pub))

        e = PrivateKey(gen_random_int(0, N), G, N)  # generate a private key
        pub = e.secret * G  # public point corresponding to e
        z = gen_random_int(0, 2 ** 256)  # generate a random message for testing
        signature: Signature = e.sign(z)
        self.assertTrue(signature.verify(z, pub))

        print(int_to_hex_str(signature, num_bits=256))
        print(int_to_hex_str(pub, num_bits=256))