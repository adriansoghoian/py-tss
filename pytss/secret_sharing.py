from typing import List
from fractions import Fraction
from math import prod as list_product
from pytss.common_crypto import (
    gen_random_int
)
from pytss.common_math import (
    compute_modular_inverse
)

def _evaluate_polynomial(coefficients: List[int], x: int, modulus: int) -> int:
    acc = coefficients[0]

    for i in range(1, len(coefficients)):
        acc = (acc + coefficients[i] * pow(x, i, modulus)) % modulus

    return acc

def split_into_shares(secret: int, n: int, t: int, finite_field_order: int) -> tuple[int, int]:
    """
        Shamir secret sharing -- masks a secret across n shares requiring a t threshold to unmask.

        Returns a list of tuples (x, f(x)) representing a share, aka evaluations of a polynomial 
        over a finite field. 
    """
    assert(n >= t)

    # generate coefficients of polynomial w/ degree threshold - 1
    # first coefficient (0th power coefficient) is our secret to be masked
    coefficients = [secret] + [ gen_random_int(1, finite_field_order) for _ in range(t - 1) ] 
    return [
        (i, _evaluate_polynomial(coefficients, i, finite_field_order)) for i in range(1, n + 1)
    ]

def recover_secret(shares: tuple[int, int], finite_field_order: int) -> int:
    secret = 0
    for i in range(len(shares)):
        l = shares[i][1]
        for j in range(len(shares)):
            if i == j: continue

            l = (l * (shares[j][0] * compute_modular_inverse(shares[j][0] - shares[i][0], finite_field_order))) % finite_field_order

        secret = (secret + l) % finite_field_order
    
    return secret
