"""
Unit tests for keylime.models.base.types.nonce module
"""

import unittest

from keylime.models.base.types.binary import Binary
from keylime.models.base.types.nonce import Nonce


class TestNonceGenerate(unittest.TestCase):
    """Test cases for Nonce.generate() static method"""

    def test_generate_128_bits(self):
        """Test generating 128-bit nonce"""
        nonce = Nonce.generate(128)

        self.assertIsInstance(nonce, bytes)
        self.assertEqual(len(nonce), 16)  # 128 bits = 16 bytes

    def test_generate_256_bits(self):
        """Test generating 256-bit nonce"""
        nonce = Nonce.generate(256)

        self.assertIsInstance(nonce, bytes)
        self.assertEqual(len(nonce), 32)  # 256 bits = 32 bytes

    def test_generate_512_bits(self):
        """Test generating 512-bit nonce"""
        nonce = Nonce.generate(512)

        self.assertIsInstance(nonce, bytes)
        self.assertEqual(len(nonce), 64)  # 512 bits = 64 bytes

    def test_generate_not_multiple_of_8_raises_error(self):
        """Test that non-multiple of 8 bits raises ValueError"""
        with self.assertRaises(ValueError) as context:
            Nonce.generate(129)  # Not multiple of 8

        self.assertIn("must receive a value which is a multiple of 8", str(context.exception))

    def test_generate_127_bits_raises_error(self):
        """Test that 127 bits (not multiple of 8) raises ValueError"""
        with self.assertRaises(ValueError) as context:
            Nonce.generate(127)

        self.assertIn("must receive a value which is a multiple of 8", str(context.exception))

    def test_generate_below_128_bits_with_enforcement_raises_error(self):
        """Test that < 128 bits with enforce_entropy=True raises ValueError"""
        with self.assertRaises(ValueError) as context:
            Nonce.generate(64, enforce_entropy=True)

        self.assertIn("should have a length of 128 bits or greater", str(context.exception))

    def test_generate_120_bits_with_enforcement_raises_error(self):
        """Test that 120 bits with enforce_entropy=True raises ValueError"""
        with self.assertRaises(ValueError) as context:
            Nonce.generate(120, enforce_entropy=True)

        self.assertIn("should have a length of 128 bits or greater", str(context.exception))

    def test_generate_below_128_bits_without_enforcement_succeeds(self):
        """Test that < 128 bits with enforce_entropy=False succeeds"""
        nonce = Nonce.generate(64, enforce_entropy=False)

        self.assertIsInstance(nonce, bytes)
        self.assertEqual(len(nonce), 8)  # 64 bits = 8 bytes

    def test_generate_8_bits_without_enforcement_succeeds(self):
        """Test that 8 bits with enforce_entropy=False succeeds"""
        nonce = Nonce.generate(8, enforce_entropy=False)

        self.assertIsInstance(nonce, bytes)
        self.assertEqual(len(nonce), 1)  # 8 bits = 1 byte

    def test_generate_produces_different_nonces(self):
        """Test that multiple generate calls produce different nonces"""
        nonce1 = Nonce.generate(128)
        nonce2 = Nonce.generate(128)

        # With high probability, two random nonces should be different
        self.assertNotEqual(nonce1, nonce2)

    def test_generate_default_enforcement_is_true(self):
        """Test that enforce_entropy defaults to True"""
        # Should raise error for < 128 bits when enforcement not specified
        with self.assertRaises(ValueError) as context:
            Nonce.generate(64)  # No enforce_entropy parameter

        self.assertIn("should have a length of 128 bits or greater", str(context.exception))

    def test_generate_exactly_128_bits_succeeds(self):
        """Test that exactly 128 bits succeeds with enforcement"""
        nonce = Nonce.generate(128, enforce_entropy=True)

        self.assertIsInstance(nonce, bytes)
        self.assertEqual(len(nonce), 16)

    def test_generate_zero_bits_succeeds(self):
        """Test that 0 bits with enforce_entropy=False returns empty bytes"""
        nonce = Nonce.generate(0, enforce_entropy=False)

        self.assertIsInstance(nonce, bytes)
        self.assertEqual(len(nonce), 0)
        self.assertEqual(nonce, b"")

    def test_generate_large_nonce(self):
        """Test generating large nonce (1024 bits)"""
        nonce = Nonce.generate(1024)

        self.assertIsInstance(nonce, bytes)
        self.assertEqual(len(nonce), 128)  # 1024 bits = 128 bytes


class TestNonceInheritance(unittest.TestCase):
    """Test cases for Nonce inheritance from Binary"""

    def test_nonce_inherits_from_binary(self):
        """Test that Nonce is a subclass of Binary"""

        self.assertTrue(issubclass(Nonce, Binary))

    def test_nonce_instance_creation(self):
        """Test creating Nonce instance"""
        nonce = Nonce()

        self.assertIsInstance(nonce, Nonce)


if __name__ == "__main__":
    unittest.main()
