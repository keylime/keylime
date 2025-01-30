"""Unit tests for Tpm.verify_tpm_object() function."""

import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from keylime.tpm.errors import IncorrectSignature, ObjectNameMismatch, QualifyingDataMismatch
from keylime.tpm.tpm_main import Tpm


class TestTpmVerifyObject(unittest.TestCase):
    """Test cases for Tpm.verify_tpm_object() error handling."""

    def test_qualifying_data_mismatch_exception(self):
        """Test that QualifyingDataMismatch is raised when qualifying data doesn't match."""
        # Generate a real RSA key for testing
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Create minimal test data
        tpm_object = b"\x00\x01" + b"\x00" * 100
        key = b"\x00\x01" + b"\x00" * 100
        # Create a minimal attest structure with mismatched qualifying data
        # Structure: magic(4) + type(2) + qualifiedSigner_size(2) + qualifiedSigner + extraData_size(2) + extraData + ...
        attest = (
            b"\xff\x54\x43\x47"  # TPM_GENERATED magic
            + b"\x00\x17"  # TPM_ST_ATTEST_CERTIFY
            + b"\x00\x04"  # qualifiedSigner size = 4
            + b"\x00\x00\x00\x00"  # qualifiedSigner data
            + b"\x00\x04"  # extraData size = 4
            + b"\x11\x22\x33\x44"  # extraData (qualifying data in attest)
            + b"\x00" * 100  # rest of structure
        )
        sig = b"\x00\x14" + b"\x00\x0b" + b"\x00\x20" + b"\x00" * 100  # Minimal signature structure
        qual = b"\x99\x88\x77\x66"  # Different from what's in attest

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            mock_pubkey.return_value = public_key

            with self.assertRaises(QualifyingDataMismatch) as context:
                Tpm.verify_tpm_object(tpm_object, key, attest, sig, qual=qual)

            self.assertIn("qualifying data does not match", str(context.exception))

    def test_object_name_mismatch_exception(self):
        """Test that ObjectNameMismatch is raised when object name doesn't match."""
        # Generate a real RSA key for testing
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        tpm_object = b"\x00\x01" + b"\x00" * 100
        key = b"\x00\x01" + b"\x00" * 100

        # Create attest structure where object name won't match
        attest = (
            b"\xff\x54\x43\x47"  # TPM_GENERATED magic
            + b"\x00\x17"  # TPM_ST_ATTEST_CERTIFY
            + b"\x00\x04"  # qualifiedSigner size
            + b"\x00\x00\x00\x00"  # qualifiedSigner
            + b"\x00\x04"  # extraData size
            + b"\x11\x22\x33\x44"  # extraData (matching qual)
            + b"\x00" * 100  # rest including object name field
        )
        sig = b"\x00\x14" + b"\x00\x0b" + b"\x00\x20" + b"\x00" * 100
        qual = b"\x11\x22\x33\x44"  # Matching qualifying data

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            with patch("keylime.tpm.tpm2_objects.get_tpm2b_public_name") as mock_name:
                mock_pubkey.return_value = public_key
                mock_name.return_value = "different_name_hash"

                with self.assertRaises(ObjectNameMismatch) as context:
                    Tpm.verify_tpm_object(tpm_object, key, attest, sig, qual=qual)

                self.assertIn("name of TPM object not found", str(context.exception))

    def test_incorrect_signature_exception(self):
        """Test that IncorrectSignature is raised when signature verification fails."""
        # Generate a real RSA key for testing
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        tpm_object = b"\x00\x01" + b"\x00" * 100
        key = b"\x00\x01" + b"\x00" * 100

        # Create a valid-looking attest structure
        attest = (
            b"\xff\x54\x43\x47"
            + b"\x00\x17"
            + b"\x00\x04"
            + b"\x00\x00\x00\x00"
            + b"\x00\x04"
            + b"\x11\x22\x33\x44"
            + b"\x00" * 100
        )
        # Create signature structure with wrong signature data
        sig = (
            b"\x00\x14"  # TPM_ALG_RSASSA
            + b"\x00\x0b"  # TPM_ALG_SHA256
            + b"\x01\x00"  # signature size = 256
            + b"\x00" * 256  # Invalid signature bytes
        )
        qual = b"\x11\x22\x33\x44"

        with patch("keylime.tpm.tpm2_objects.pubkey_from_tpm2b_public") as mock_pubkey:
            with patch("keylime.tpm.tpm2_objects.get_tpm2b_public_name") as mock_name:
                with patch("keylime.tpm.tpm_util.crypt_hash") as mock_hash:
                    mock_pubkey.return_value = public_key
                    # Make name check pass by returning matching hash
                    mock_name.return_value = "00" * 34  # Will match attest[offset:offset+34]
                    mock_hash.return_value = (b"digest_data", hashes.SHA256())

                    # Mock verify to raise InvalidSignature
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
            # Return an unsupported key type
            mock_pubkey.return_value = "not_a_supported_key_type"

            with self.assertRaises(ValueError) as context:
                Tpm.verify_tpm_object(tpm_object, key, attest, sig)

            self.assertIn("Unsupported key type", str(context.exception))


if __name__ == "__main__":
    unittest.main()
