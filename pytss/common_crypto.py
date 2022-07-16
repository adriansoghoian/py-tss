import secrets
import random
from typing import List
import hashlib

INITIAL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 
    61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 
    131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 
    193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 
    269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 
    349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 
    503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 
    599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 
    673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 
    761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 
    857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 
    947, 953, 967, 971, 977, 983, 991, 997
]

MILLER_RABIN_ROUNDS = 25

def gen_random_int(lower, upper) -> int:
    return random.randint(lower, upper - 1)

def prime_of_n_bits(n) -> int:     
    candidate = secrets.randbits(n)
    while not is_prime(candidate):
        if candidate % 2 == 0:
            candidate += 1
        else:
            candidate += 2

    return candidate

def is_prime(candidate, miller_rabin_rounds=MILLER_RABIN_ROUNDS) -> bool:
    if candidate <= INITIAL_PRIMES[-1]:
        return candidate in INITIAL_PRIMES

    for p in INITIAL_PRIMES:
        if candidate % p == 0:
            return False

    return miller_rabin(candidate, miller_rabin_rounds)

def miller_rabin(candidate, rounds) -> bool:
    d = candidate - 1
    r = 0

    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds): 
        rand_witness = random.randint(2, candidate-2)
        x = pow(rand_witness, d, candidate)

        if x != 1:
            i = 0
            while x != (candidate - 1):
                if i == r - 1:
                    return False
                else:
                    i = i + 1
                    x = (x ** 2) % candidate

    return True

def sha256_values(values: List[int]) -> int:
    hash_delimeter = "#"
    hashable_bytes = hash_delimeter.join([ str(each) for each in values ]).encode()
    return int.from_bytes(hashlib.sha256(hashable_bytes).digest(), byteorder='big')
    
