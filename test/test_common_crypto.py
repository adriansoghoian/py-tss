import unittest
from pytss.common_crypto import (
    sha256_values
)

class TestCommonCrypto(unittest.TestCase):

    def test_sha256_list(self):
        values = [1, 2, 3]
        print(sha256_values(values))