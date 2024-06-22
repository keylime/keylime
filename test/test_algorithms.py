import os
import tempfile
import unittest

from keylime.common.algorithms import Encrypt, Hash, Sign


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

    def test_is_recognized(self):
        test_cases = [
            {
                "hash": "foobar",
                "valid": False,
            },
            {
                "hash": "sha1",
                "valid": True,
            },
            {
                "hash": "",
                "valid": False,
            },
            {
                "hash": "sm3_256",
                "valid": True,
            },
        ]

        for c in test_cases:
            self.assertEqual(Hash.is_recognized(c["hash"]), c["valid"])

    def test_hexdigest_len(self):
        test_cases = [
            {"hash": "sha1", "len": 40},
            {"hash": "sha256", "len": 64},
            {"hash": "sha384", "len": 96},
            {"hash": "sha512", "len": 128},
            {
                "hash": "sm3_256",
                "len": 64,
            },
        ]

        for c in test_cases:
            self.assertEqual(Hash(c["hash"]).hexdigest_len(), c["len"])

    def test_file_digest(self):
        contents = "x" * (1024 * 1024)
        test_cases = [
            {
                "hash": "sha1",
                "digest": "e37f4d5be56713044d62525e406d250a722647d6",
            },
            {
                "hash": "sha256",
                "digest": "8f990ba0b577b51cf009ea049368c16bbda1b21e1b93be07a824758bb253c39b",
            },
            {
                "hash": "sha384",
                "digest": "f0ec47c12284409dcd83c83d865d261c5cba38a686ae10b138972c8b086f89426c0f17a52f1483ef49ba6fc594932508",
            },
            {
                "hash": "sha512",
                "digest": "d42a194e9f95d26282ff043c788a39cd16b658462aafcbd978974c93733bc270f887e5689eb28710dad31ef992cec4fc7979a6ff2d12cd5a9986bc5442ab22ab",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            targetfile = os.path.join(tmpdir, "dummy-file")
            with open(targetfile, "w", encoding="UTF-8") as mfile:
                mfile.write(contents)

            for c in test_cases:
                self.assertEqual(Hash(c["hash"]).file_digest(targetfile), c["digest"], msg=f"hash = {c['hash']}")


class TestEncrypt(unittest.TestCase):
    def test_is_recognized(self):
        test_cases = [
            {
                "enc": "foobar",
                "valid": False,
            },
            {
                "enc": "rsa",
                "valid": True,
            },
            {
                "enc": "",
                "valid": False,
            },
            {
                "enc": "ecc",
                "valid": True,
            },
        ]

        for c in test_cases:
            self.assertEqual(Encrypt.is_recognized(c["enc"]), c["valid"], msg=f"enc = {c['enc']}")


class TestSign(unittest.TestCase):
    def test_is_recognized(self):
        test_cases = [
            {
                "sign": "foobar",
                "valid": False,
            },
            {
                "sign": "rsassa",
                "valid": True,
            },
            {
                "sign": "rsapss",
                "valid": True,
            },
            {
                "sign": "",
                "valid": False,
            },
            {
                "sign": "ecdsa",
                "valid": True,
            },
            {
                "sign": "ecdaa",
                "valid": True,
            },
            {
                "sign": "ecschnorr",
                "valid": True,
            },
        ]

        for c in test_cases:
            self.assertEqual(Sign.is_recognized(c["sign"]), c["valid"], msg=f"sign = {c['sign']}")
