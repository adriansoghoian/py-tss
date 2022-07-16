import unittest
from pytss.utils import (
    Converters
)

class TestUtils(unittest.TestCase):

    def test_serialize_strings_to_ints(self):
        msgs = [
            "hello this is a test!",
            "Hello, World, عالَم, ދުނިޔެ, जगत, 世界",
            "@#$&&@#$!!!"
        ]
        for msg in msgs:
            msg_as_int = Converters.string_to_int(msg)
            self.assertTrue(isinstance(msg_as_int, int))

            msg_back_as_string = Converters.int_to_string(msg_as_int)
            self.assertEqual(msg, msg_back_as_string)
    