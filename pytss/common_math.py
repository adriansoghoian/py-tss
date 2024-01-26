from collections import namedtuple

ExtendedEuclidianResult = namedtuple("ExtendedEuclidianResult", "bezout_x bezout_y gcd")

# This implementation is taken from: https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python

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

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def compute_modular_sqrt(a, modulo_base):
    if legendre_symbol(a, modulo_base) != 1:
        return 0
    elif a == 0:
        return 0
    elif modulo_base == 2:
        return modulo_base
    elif modulo_base % 4 == 3:
        return pow(a, (modulo_base + 1) // 4, modulo_base)

    s = modulo_base - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    n = 2
    while legendre_symbol(n, modulo_base) != -1:
        n += 1

    x = pow(a, (s + 1) // 2, modulo_base)
    b = pow(a, s, modulo_base)
    g = pow(n, s, modulo_base)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, modulo_base)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), modulo_base)
        g = (gs * gs) % modulo_base
        x = (x * gs) % modulo_base
        b = (b * g) % modulo_base
        r = m
