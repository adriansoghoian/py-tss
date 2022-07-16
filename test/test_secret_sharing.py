import unittest
from pytss.secret_sharing import (
    split_into_shares,
    recover_secret
)
import random

PRIME = 2 ** 127 - 1

class TestSecretSharing(unittest.TestCase):

    def test_recover_secret_all_shares(self):
        secret = 1234
        n = 6 
        t = 3 

        shares = split_into_shares(secret, n, t, PRIME)
        recovered_secret = recover_secret(shares, PRIME)
        self.assertEqual(secret, recovered_secret)

    def test_recover_secret_threshold_shares(self):
        secret = 1234
        n = 6 
        t = 3 

        shares = split_into_shares(secret, n, t, PRIME)
        # try with first 3 shares
        recovered_secret = recover_secret(shares[0:3], PRIME)
        self.assertEqual(secret, recovered_secret)

        # try with random set of 3 shares
        recovery_shares = random.sample(shares, 3)
        recovered_secret = recover_secret(recovery_shares, PRIME)
        self.assertEqual(secret, recovered_secret)

    def test_does_not_recover_secret_less_thanthreshold_shares(self):
        secret = 1234
        n = 8
        t = 4 

        shares = split_into_shares(secret, n, t, PRIME)
        recovered_secret = recover_secret(shares[0:3], PRIME)
        self.assertNotEqual(secret, recovered_secret)

    def test_recover_with_actual_values(self):
        tuples = [
            (1, 53672893317935545298233520515892478133190587113913092247007643730153094198702), 
            (2, 11756452553755548434376720331354453472244248857358553412297278872967058897590), 
            (3, 85632101026891746994090905155504336664567895266444578617044498023689858268141)
        ]
        # n = 3
        # t = 2
        prime = 115792089237316195423570985008687907853269984665640564039457584007908834671663
        secret = 95589334082115542162090320700430502794136925370467631081718008587339129499814
        recovered_secret = recover_secret(tuples[0:2], prime)

        self.assertEqual(recovered_secret, secret)
