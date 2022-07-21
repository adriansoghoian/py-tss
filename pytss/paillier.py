import base64
from typing import Tuple
from .common_crypto import (
    prime_of_n_bits,
    gen_random_int
)
from .utils import (
    chunks,
    Converters
)

DEFAULT_BITS = 3072

class PaillierPublicKey:

    def __init__(self, n: int, r: int, size: int):
        self.n = n 
        self.g = n + 1
        self.r = r
        self.n_squared = n * n
        self.size = size

    def encrypt(self, pt: int) -> int:
        assert pt.bit_length() <= self.size, "Plaintext too large"
        return (pow(self.g, pt, self.n_squared) * pow(self.r, self.n, self.n_squared)) % self.n_squared

    def encrypt_bytes(self, pt: bytes) -> bytes:
        bytes_per_chunk = self.size // 8 
        enc_bytes = [ 
            Converters.int_to_bytes(
                self.encrypt(Converters.bytes_to_int(chunk)),
                bytes_per_chunk * 2
            ) for chunk in chunks(pt, bytes_per_chunk) 
        ]

        return b"".join(enc_bytes)

    def encrypt_string(self, pt: str) -> str:
        enc_bytes = self.encrypt_bytes(pt.encode())
        return base64.b64encode(enc_bytes)

    def homomorphic_multiply(self, ct: int, pt: int) -> int:
        return pow(ct, pt, self.n_squared)

    def homomorphic_add(self, ct: int, pt: int) -> int:
        return (ct * self.encrypt(pt)) % self.n_squared
        
class PaillierPrivateKey:

    def __init__(self, p: int, q: int, size: int):
        self.p = p
        self.q = q
        self.n = p * q
        self.g = self.n + 1
        self.n_squared = self.n**2
        self.lam = self.phi = (p - 1)*(q - 1)
        self.mu = pow(self.lam, -1, self.n)
        self.size = size

    def decrypt(self, ct: int) -> int:
        return ((self._l_function(pow(ct, self.lam, self.n_squared))) * self.mu) % self.n

    def decrypt_bytes(self, ct: bytes) -> bytes:
        decrypted_bytes = [ 
            Converters.int_to_bytes(
                self.decrypt(Converters.bytes_to_int(each)),
                self.size // 8
            ).strip(b'\x00') for each in chunks(ct, self.size // 4) 
        ]
        return b"".join(decrypted_bytes) 

    def decrypt_b64(self, ct: str) -> str:
        enc_bytes = base64.b64decode(ct)
        dec_bytes = self.decrypt_bytes(enc_bytes)
        return dec_bytes.decode()

    def _l_function(self, x):
        return (x - 1) // self.n

def generate_key_pair(size=DEFAULT_BITS) -> Tuple[PaillierPublicKey, PaillierPrivateKey]:
    p = q = n = None
    n_len = 0

    while n_len != size:
        p = q = prime_of_n_bits(size // 2)
        while q == p:
            q = prime_of_n_bits(size // 2)

        n = p * q
        n_len = n.bit_length()

    r = gen_random_int(0, n)
    public_key = PaillierPublicKey(n, r, size)
    private_key = PaillierPrivateKey(p, q, size)

    return public_key, private_key