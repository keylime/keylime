import unittest

from keylime.common.algorithms import Hash


class TestHash(unittest.TestCase):
    def test_constructor_pass(self):
        for algo in ["sha256", "sha384", "sha512"]:
            self.assertIsInstance(Hash(algo), Hash)

    def test_constructor_fail(self):
        try:
            # Must never get here
            self.assertNotIsInstance(Hash("bad"), Hash)
        except Exception as e:
            self.assertIsInstance(e, ValueError)

    def test_enum_pass(self):
        self.assertTrue(Hash.SHA1 in Hash)
        self.assertTrue(Hash.SHA256 in Hash)
        self.assertTrue(Hash.SHA384 in Hash)
        self.assertTrue(Hash.SHA512 in Hash)
        self.assertTrue(Hash.SM3_256 in Hash)

    def test_hashing(self):
        self.assertEqual(
            Hash.SHA256.hash(b""),
            b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U",
        )
