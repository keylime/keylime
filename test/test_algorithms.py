import os
import tempfile
import unittest

from keylime.common.algorithms import Encrypt, Hash, Sign, is_accepted


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
            {
                "enc": "ecc192",
                "valid": True,
            },
            {
                "enc": "ecc224",
                "valid": True,
            },
            {
                "enc": "ecc256",
                "valid": True,
            },
            {
                "enc": "ecc384",
                "valid": True,
            },
            {
                "enc": "ecc521",
                "valid": True,
            },
        ]

        for c in test_cases:
            self.assertEqual(Encrypt.is_recognized(c["enc"]), c["valid"], msg=f"enc = {c['enc']}")

    def test_enum_membership(self):
        """Test that all ECC curve algorithms are members of the Encrypt enum"""
        self.assertTrue(Encrypt.RSA in Encrypt)
        self.assertTrue(Encrypt.ECC in Encrypt)
        self.assertTrue(Encrypt.ECC192 in Encrypt)
        self.assertTrue(Encrypt.ECC224 in Encrypt)
        self.assertTrue(Encrypt.ECC256 in Encrypt)
        self.assertTrue(Encrypt.ECC384 in Encrypt)
        self.assertTrue(Encrypt.ECC521 in Encrypt)

    def test_normalize(self):
        """Test the normalize method for handling ECC aliases"""
        test_cases = [
            {
                "input": "ecc",
                "expected": "ecc256",
            },
            {
                "input": "ecc192",
                "expected": "ecc192",
            },
            {
                "input": "ecc224",
                "expected": "ecc224",
            },
            {
                "input": "ecc256",
                "expected": "ecc256",
            },
            {
                "input": "ecc384",
                "expected": "ecc384",
            },
            {
                "input": "ecc521",
                "expected": "ecc521",
            },
            {
                "input": "rsa",
                "expected": "rsa2048",
            },
        ]

        for c in test_cases:
            self.assertEqual(Encrypt.normalize(c["input"]), c["expected"], msg=f"input = {c['input']}")

    def test_normalize_ecc_alias_behavior(self):
        """Test that ECC alias normalization matches agent behavior"""
        # Test that "ecc" is recognized through alias handling
        self.assertTrue(Encrypt.is_recognized("ecc"))

        # Test that normalize converts "ecc" to "ecc256" (P-256)
        self.assertEqual(Encrypt.normalize("ecc"), "ecc256")

        # Test that direct ecc256 works
        self.assertTrue(Encrypt.is_recognized("ecc256"))

    def test_normalize_rsa_alias_behavior(self):
        """Test that RSA alias normalization matches agent behavior"""
        # Test that "rsa" is recognized through alias handling
        self.assertTrue(Encrypt.is_recognized("rsa"))

        # Test that normalize converts "rsa" to "rsa2048"
        self.assertEqual(Encrypt.normalize("rsa"), "rsa2048")

        # Test that direct rsa2048 works
        self.assertTrue(Encrypt.is_recognized("rsa2048"))


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


class TestIsAccepted(unittest.TestCase):
    def test_direct_algorithm_matching(self):
        """Test that direct algorithm matches work correctly"""
        test_cases = [
            {
                "algorithm": "ecc256",
                "accepted": ["ecc256"],
                "expected": True,
            },
            {
                "algorithm": "rsa",
                "accepted": ["rsa"],
                "expected": True,
            },
            {
                "algorithm": "ecc384",
                "accepted": ["ecc256", "ecc384"],
                "expected": True,
            },
            {
                "algorithm": "ecc521",
                "accepted": ["ecc256"],
                "expected": False,
            },
            {
                "algorithm": "unknown",
                "accepted": ["rsa", "ecc256"],
                "expected": False,
            },
        ]

        for c in test_cases:
            result = is_accepted(c["algorithm"], c["accepted"])
            self.assertEqual(result, c["expected"], msg=f"algorithm='{c['algorithm']}', accepted={c['accepted']}")

    def test_backwards_compatibility_ecc_normalization(self):
        """Test backwards compatibility: 'ecc' in accepted list should accept specific ECC algorithms"""
        test_cases = [
            {
                "algorithm": "ecc256",
                "accepted": ["ecc"],
                "expected": True,
                "desc": "ecc256 should be accepted when 'ecc' is in accepted list",
            },
            {
                "algorithm": "ecc384",
                "accepted": ["ecc"],
                "expected": False,
                "desc": "ecc384 should NOT be accepted when only 'ecc' is in accepted list (ecc maps to ecc256)",
            },
            {
                "algorithm": "ecc521",
                "accepted": ["ecc"],
                "expected": False,
                "desc": "ecc521 should NOT be accepted when only 'ecc' is in accepted list",
            },
            {
                "algorithm": "ecc192",
                "accepted": ["ecc"],
                "expected": False,
                "desc": "ecc192 should NOT be accepted when only 'ecc' is in accepted list",
            },
        ]

        for c in test_cases:
            result = is_accepted(c["algorithm"], c["accepted"])
            self.assertEqual(
                result, c["expected"], msg=f"{c['desc']} - algorithm='{c['algorithm']}', accepted={c['accepted']}"
            )

    def test_forward_compatibility_ecc_normalization(self):
        """Test forward compatibility: specific ECC in accepted list should accept 'ecc' algorithm"""
        test_cases = [
            {
                "algorithm": "ecc",
                "accepted": ["ecc256"],
                "expected": True,
                "desc": "ecc should be accepted when 'ecc256' is in accepted list (both normalize to ecc256)",
            },
            {
                "algorithm": "ecc",
                "accepted": ["ecc384"],
                "expected": False,
                "desc": "ecc should NOT be accepted when only 'ecc384' is in accepted list",
            },
            {
                "algorithm": "ecc",
                "accepted": ["ecc521"],
                "expected": False,
                "desc": "ecc should NOT be accepted when only 'ecc521' is in accepted list",
            },
        ]

        for c in test_cases:
            result = is_accepted(c["algorithm"], c["accepted"])
            self.assertEqual(
                result, c["expected"], msg=f"{c['desc']} - algorithm='{c['algorithm']}', accepted={c['accepted']}"
            )

    def test_bidirectional_algorithm_matching(self):
        """Test bidirectional matching scenarios that happen in real usage"""
        test_cases = [
            {
                "algorithm": "ecc256",
                "accepted": ["rsa", "ecc"],
                "expected": True,
                "desc": "Agent reports ecc256, tenant config has generic 'ecc'",
            },
            {
                "algorithm": "ecc",
                "accepted": ["rsa", "ecc256"],
                "expected": True,
                "desc": "Agent reports generic 'ecc', tenant config has specific 'ecc256'",
            },
            {
                "algorithm": "ecc384",
                "accepted": ["rsa", "ecc"],
                "expected": False,
                "desc": "Agent reports ecc384, tenant has generic 'ecc' (should not match)",
            },
            {
                "algorithm": "ecc",
                "accepted": ["rsa", "ecc384"],
                "expected": False,
                "desc": "Agent reports generic 'ecc', tenant has ecc384 (should not match)",
            },
        ]

        for c in test_cases:
            result = is_accepted(c["algorithm"], c["accepted"])
            self.assertEqual(
                result, c["expected"], msg=f"{c['desc']} - algorithm='{c['algorithm']}', accepted={c['accepted']}"
            )

    def test_mixed_algorithm_types(self):
        """Test mixing different algorithm types in accepted list"""
        test_cases = [
            {
                "algorithm": "rsa",
                "accepted": ["ecc", "rsa"],
                "expected": True,
            },
            {
                "algorithm": "ecc256",
                "accepted": ["rsa", "ecc"],
                "expected": True,
            },
            {
                "algorithm": "ecc384",
                "accepted": ["rsa", "ecc256", "ecc384"],
                "expected": True,
            },
            {
                "algorithm": "unknown",
                "accepted": ["rsa", "ecc", "ecc384"],
                "expected": False,
            },
        ]

        for c in test_cases:
            result = is_accepted(c["algorithm"], c["accepted"])
            self.assertEqual(result, c["expected"], msg=f"algorithm='{c['algorithm']}', accepted={c['accepted']}")

    def test_edge_cases(self):
        """Test edge cases and boundary conditions"""
        test_cases = [
            {"algorithm": "", "accepted": ["ecc"], "expected": False, "desc": "Empty algorithm string"},
            {"algorithm": "ecc256", "accepted": [], "expected": False, "desc": "Empty accepted list"},
            {"algorithm": "ecc256", "accepted": [""], "expected": False, "desc": "Accepted list with empty string"},
            {
                "algorithm": "ECC256",
                "accepted": ["ecc256"],
                "expected": False,
                "desc": "Case sensitivity - uppercase should not match",
            },
            {
                "algorithm": "ecc256",
                "accepted": ["ecc"],
                "expected": True,
                "desc": "ecc256 algorithm should match ecc in accepted list",
            },
            {
                "algorithm": "ecc",
                "accepted": ["ecc256"],
                "expected": True,
                "desc": "ecc algorithm should match ecc256 in accepted list",
            },
        ]

        for c in test_cases:
            result = is_accepted(c["algorithm"], c["accepted"])
            self.assertEqual(
                result, c["expected"], msg=f"{c['desc']} - algorithm='{c['algorithm']}', accepted={c['accepted']}"
            )
