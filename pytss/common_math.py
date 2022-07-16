from collections import namedtuple

ExtendedEuclidianResult = namedtuple("ExtendedEuclidianResult", "bezout_x bezout_y gcd")

def extended_euclidian(a, b):
    old_r, r = a, b 
    old_s, s = 1, 0 
    old_t, t = 0, 1 

    while r != 0:
        quotient = old_r // r 
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s 
        old_t, t = t, old_t - quotient * t 

    return ExtendedEuclidianResult(old_s, old_t, old_r)

def compute_modular_inverse(a, modulo_base):
    ee_result = extended_euclidian(a, modulo_base)
    return ee_result.bezout_x % modulo_base