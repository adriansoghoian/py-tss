import unittest
from pytss.common_math import (
    compute_modular_inverse,
    compute_modular_sqrt
)

class TestCommonMath(unittest.TestCase):

    def test_compute_modular_inverse(self):
        self.assertEqual(compute_modular_inverse(15, 26), 7)

    def test_compute_modular_inverse_large(self):
        n = 102112097946582615631136147902109156622653898419035298906688331069201061233983
        p = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        expected = 25474184976837862363894976995466454035326651076879946883050318548976065133305
        self.assertEqual(compute_modular_inverse(n, p), expected)

        n = 2592341508477388788338039875332086003935577462794292637336102309357423871672
        p = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        expected = 77350129032275108437581484883529059659442577067104103137820664936133073361349
        self.assertEqual(compute_modular_inverse(n, p), expected)

    def test_compute_modular_sqrt(self):
        self.assertEqual(compute_modular_sqrt(223, 17), 6)