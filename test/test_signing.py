"""
SPDX-License-Identifier: Apache-2.0
Copyright 2022 Red Hat, Inc.
"""

import unittest
from pathlib import Path

from keylime import signing

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
TEST_FILES = f"{PACKAGE_ROOT}/test-data/files"


class TestSigning(unittest.TestCase):
    def test_sign_gpg(self):
        try:
            signing.verify_signature_from_file(
                f"{TEST_FILES}/allowlist-pgp-key.pgp",
                f"{TEST_FILES}/allowlist.json",
                f"{TEST_FILES}/allowlist-pgp-sig.sig",
                "Testing Allowlist",
            )
        except Exception as e:
            self.fail(f"Signing raised exception: {e}!")

    def test_sign_ec(self):
        try:
            signing.verify_signature_from_file(
                f"{TEST_FILES}/allowlist-ec-key.pem",
                f"{TEST_FILES}/allowlist.json",
                f"{TEST_FILES}/allowlist-ec-sig.bin",
                "Testing Allowlist",
            )
        except Exception as e:
            self.fail(f"Signing raised exception: {e}!")

    def test_sign_bad_sig(self):
        try:
            signing.verify_signature_from_file(
                f"{TEST_FILES}/allowlist-pgp-key.pgp",
                f"{TEST_FILES}/allowlist.json",
                f"{TEST_FILES}/allowlist-invalid-sig.sig",
                "Testing Allowlist",
            )
            self.fail("Signing passed with invalid signature!")
        except Exception:
            pass
