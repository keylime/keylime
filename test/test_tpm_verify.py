"""Unit tests for Tpm.verify_tpm_object() function."""

import struct
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from keylime.tpm.errors import IncorrectSignature, ObjectNameMismatch, QualifyingDataMismatch
from keylime.tpm.tpm_main import Tpm

# 34-byte AK name: nameAlg(2) + SHA-256 digest(32)
_AK_NAME = b"\x00\x0b" + b"\xaa" * 32


def _build_certify_attest(extra_data: bytes, certify_name: bytes) -> bytes:
    """Build a minimal TPMS_ATTEST structure for TPM_ST_ATTEST_CERTIFY."""
    header = b"\xff\x54\x43\x47" + b"\x80\x17"
    qualified_signer = struct.pack(">H", 4) + b"\x00" * 4
    extra_data_field = struct.pack(">H", len(extra_data)) + extra_data
    clock_info = b"\x00" * 17
    firmware_version = b"\x00" * 8
    name_field = struct.pack(">H", len(certify_name)) + certify_name
    qualified_name = struct.pack(">H", 2) + b"\x00\x00"
    return header + qualified_signer + extra_data_field + clock_info + firmware_version + name_field + qualified_name


class TestTpmVerifyObject(unittest.TestCase):
    """Test cases for Tpm.verify_tpm_object() error handling."""

    def test_qualifying_data_mismatch_exception(self):
        """Test that QualifyingDataMismatch is raised when qualifying data doesn't match."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        tpm_object = b"\x00\x01" + b"\x00" * 100
        key = b"\x00\x01" + b"\x00" * 100
        attest = _build_certify_attest(b"\x11\x22\x33\x44", _AK_NAME)
        sig = b"\x00\x14" + b"\x00\x0b" + b"\x00\x20" + b"\x00" * 100
        qual = b"\x99\x88\x77\x66"  # Different from what's in attest

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            mock_pubkey.return_value = public_key

            with self.assertRaises(QualifyingDataMismatch) as context:
                Tpm.verify_tpm_object(tpm_object, key, attest, sig, qual=qual)

            self.assertIn("qualifying data does not match", str(context.exception))

    def test_object_name_mismatch_exception(self):
        """Test that ObjectNameMismatch is raised when object name doesn't match."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        tpm_object = b"\x00\x01" + b"\x00" * 100
        key = b"\x00\x01" + b"\x00" * 100
        qual = b"\x11\x22\x33\x44"
        attest = _build_certify_attest(qual, _AK_NAME)
        sig = b"\x00\x14" + b"\x00\x0b" + b"\x00\x20" + b"\x00" * 100

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            with patch("keylime.tpm.tpm2_objects.get_tpm2b_public_name") as mock_name:
                mock_pubkey.return_value = public_key
                mock_name.return_value = "different_name_hash"

                with self.assertRaises(ObjectNameMismatch) as context:
                    Tpm.verify_tpm_object(tpm_object, key, attest, sig, qual=qual)

                self.assertIn("name of TPM object not found", str(context.exception))

    def test_incorrect_signature_exception(self):
        """Test that IncorrectSignature is raised when signature verification fails."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        tpm_object = b"\x00\x01" + b"\x00" * 100
        key = b"\x00\x01" + b"\x00" * 100
        qual = b"\x11\x22\x33\x44"
        attest = _build_certify_attest(qual, _AK_NAME)
        sig = (
            b"\x00\x14"  # TPM_ALG_RSASSA
            + b"\x00\x0b"  # TPM_ALG_SHA256
            + b"\x01\x00"  # signature size = 256
            + b"\x00" * 256
        )

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            with patch("keylime.tpm.tpm2_objects.get_tpm2b_public_name") as mock_name:
                with patch("keylime.tpm.tpm_util.crypt_hash") as mock_hash:
                    mock_pubkey.return_value = public_key
                    mock_name.return_value = _AK_NAME.hex()
                    mock_hash.return_value = (b"digest_data", hashes.SHA256())

                    with patch("keylime.tpm.tpm_util.verify") as mock_verify:
                        mock_verify.side_effect = InvalidSignature("Signature verification failed")

                        with self.assertRaises(IncorrectSignature) as context:
                            Tpm.verify_tpm_object(tpm_object, key, attest, sig, qual=qual)

                        self.assertIn("signature does not verify", str(context.exception))

    def test_unsupported_key_type_exception(self):
        """Test that ValueError is raised for unsupported key types."""
        tpm_object = b"\x00\x01" + b"\x00" * 100
        key = b"\x00\x01" + b"\x00" * 100
        attest = b"\x00" * 100
        sig = b"\x00" * 100

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            mock_pubkey.return_value = "not_a_supported_key_type"

            with self.assertRaises(ValueError) as context:
                Tpm.verify_tpm_object(tpm_object, key, attest, sig)

            self.assertIn("Unsupported key type", str(context.exception))

    def test_invalid_magic_raises(self):
        """Test that ObjectNameMismatch is raised when the magic number is wrong."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        key = b"\x00\x01" + b"\x00" * 100
        tpm_object = b"\x00\x01" + b"\x00" * 100
        # Corrupt the magic number (first 4 bytes)
        bad_attest = b"\xde\xad\xbe\xef" + b"\x80\x17" + b"\x00" * 50
        sig = b"\x00\x14" + b"\x00\x0b" + b"\x00\x20" + b"\x00" * 100

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            mock_pubkey.return_value = public_key

            with self.assertRaises(ObjectNameMismatch) as context:
                Tpm.verify_tpm_object(tpm_object, key, bad_attest, sig)

            self.assertIn("invalid magic", str(context.exception))

    def test_wrong_structure_type_raises(self):
        """Test that ObjectNameMismatch is raised when the structure type is not CERTIFY."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        key = b"\x00\x01" + b"\x00" * 100
        tpm_object = b"\x00\x01" + b"\x00" * 100
        # Valid magic but wrong type: 0x8018 = TPM_ST_ATTEST_QUOTE
        bad_attest = b"\xff\x54\x43\x47" + b"\x80\x18" + b"\x00" * 50
        sig = b"\x00\x14" + b"\x00\x0b" + b"\x00\x20" + b"\x00" * 100

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            mock_pubkey.return_value = public_key

            with self.assertRaises(ObjectNameMismatch) as context:
                Tpm.verify_tpm_object(tpm_object, key, bad_attest, sig)

            self.assertIn("invalid magic", str(context.exception))


if __name__ == "__main__":
    unittest.main()
