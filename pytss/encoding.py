from .elliptic_curve import (
    Point, 
    PrivateKey
)

def encode_public_key_to_der(pub_key: Point) -> bytes:
    return _convert_pub_key(pub_key).toDer()

def encode_public_key_to_pem(pub_key: Point) -> str:
    return _convert_pub_key(pub_key).toPem()

def encode_secret_key_to_der(sec_key: PrivateKey) -> bytes: 
    return _convert_sec_key(sec_key).toDer()

def encode_secret_key_to_pem(sec_key: PrivateKey) -> str: 
    return _convert_sec_key(sec_key).toPem()

def _convert_pub_key(pub_key: Point):
    from ellipticcurve.curve import secp256k1 as libsecp256k1
    from ellipticcurve.publicKey import PublicKey as libPublicKey
    from ellipticcurve.point import Point as libPoint

    converted_public_key = libPublicKey(
        point=libPoint(
            x=pub_key.x.value, 
            y=pub_key.y.value
        ),
        curve=libsecp256k1
    )

    return converted_public_key

def _convert_sec_key(sec_key: PrivateKey):
    from ellipticcurve.curve import secp256k1 as libsecp256k1
    from ellipticcurve.privateKey import PrivateKey as libPrivateKey

    converted_sec_key = libPrivateKey(
        curve=libsecp256k1, 
        secret=sec_key.secret
    )

    return converted_sec_key