import unittest
from pytss.paillier import generate_key_pair
from pytss.utils import (
    Converters
)

class TestPrimeGeneration(unittest.TestCase):

    def test_encrypt_ints(self):
        public, private = generate_key_pair(key_size=128)
        message = 503871685875809544500323809344413608
        encrypted = public.encrypt(message)
        decrypted = private.decrypt(encrypted)
        self.assertNotEqual(message, encrypted)
        self.assertEqual(message, decrypted)

    def test_encrypt_text(self):
        sample_text = "hi, its me!"
        public, private = generate_key_pair(key_size=128)

        encrypted = public.encrypt(Converters.string_to_int(sample_text))
        decrypted = Converters.int_to_string(private.decrypt(encrypted))
        self.assertEqual(decrypted, sample_text)
    
    def test_encrypt_long_text(self):
        sample_text = (
            "Lorem Ipsum "
            "of the printing and typesetting industry. " 
            "Lorem Ipsum has been the industry's standard" 
            "dummy text ever since the 1500s, when an unknown "
            "printer took a galley of type and scrambled it to" 
            "make a type specimen book. It has survived not only"
            "five centuries, but also the leap into electronic"
            "typesetting, remaining essentially unchanged. It was"
            "popularised in the 1960s with the release of Letraset" 
            "sheets containing Lorem Ipsum passages, and more recently" 
            "with desktop publishing software like Aldus PageMaker" 
            "including versions of Lorem Ipsum."
        )

        public, private = generate_key_pair(key_size=128)

        encrypted = public.encrypt_string(sample_text)
        decrypted = private.decrypt_b64(encrypted)
        self.assertEqual(decrypted, sample_text)

    def test_homomorphic_plaintext_add(self):
        plaintext_a = 5 
        plaintext_b = 6 

        public, private = generate_key_pair(key_size=128)
        
        ciphertext_a = public.encrypt(plaintext_a)
        ciphertext_product = public.homomorphic_add(ciphertext_a, plaintext_b)
        decrypted_ciphertext_product = private.decrypt(ciphertext_product)
        
        plaintext_sum = 11 # 5 + 6 
        self.assertEqual(plaintext_sum, decrypted_ciphertext_product)

    def test_homomorphic_plaintext_multiply(self):
        constant = 11
        message = 25

        public, private = generate_key_pair(key_size=128)

        encrypted_message = public.encrypt(message)
        homomorphic_product = public.homomorphic_multiply(encrypted_message, constant)
        
        decrypted = private.decrypt(homomorphic_product)
        self.assertEqual(message * constant, decrypted)
