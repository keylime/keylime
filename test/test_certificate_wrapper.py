"""
Unit tests for the CertificateWrapper class.

This module tests the certificate wrapper functionality that preserves original bytes
for malformed certificates requiring pyasn1 re-encoding.
"""

import base64
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.codec.der import decoder as pyasn1_decoder
from pyasn1.codec.der import encoder as pyasn1_encoder
from pyasn1_modules import rfc2459 as pyasn1_rfc2459

from keylime.certificate_wrapper import CertificateWrapper, wrap_certificate


class TestCertificateWrapper(unittest.TestCase):
    """Test cases for CertificateWrapper class."""

    def setUp(self):
        """Set up test fixtures."""
        # Malformed certificate (Base64 encoded) that requires pyasn1 re-encoding
        # This is a real TPM certificate that doesn't strictly follow ASN.1 DER rules
        self.malformed_cert_b64 = (
            "MIIDUjCCAvegAwIBAgILAI5xYHQ14nH5hdYwCgYIKoZIzj0EAwIwVTFTMB8GA1UEAxMYTnV2b3Rv"
            "biBUUE0gUm9vdCBDQSAyMTExMCUGA1UEChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9u"
            "MAkGA1UEBhMCVFcwHhcNMTkwNzIzMTcxNTEzWhcNMzkwNzE5MTcxNTEzWjAAMIIBIjANBgkqhkiG"
            "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk8kCj7srY/Zlvm1795fVXdyX44w5qsd1m5VywMDgSOavzPKO"
            "kgbHgQNx6Ak5+4Q43EJ/5qsaDBv59F8W7K69maUwcMNq1xpuq0V/LiwgJVAtc3CdvlxtwQrn7+Uq"
            "ieIGf+i8sGxpeUCSmYHJPTHNHqjQnvUtdGoy/+WO0i7WsAvX3k/gHHr4p58a8urjJ1RG2Lk1g48D"
            "ESwl+D7atQEPWzgjr6vK/s5KpLrn7M+dh97TUbG1510AOWBPP35MtT8IZbqC4hs2Ol16gT1M3a9e"
            "+GaMZkItLUwV76vKDNEgTZG8M1C9OItA/xwzlfXbPepzpxWb4kzHS4qZoQtl4vBZrQIDAQABo4IB"
            "NjCCATIwUAYDVR0RAQH/BEYwRKRCMEAxPjAUBgVngQUCARMLaWQ6NEU1NDQzMDAwEAYFZ4EFAgIT"
            "B05QQ1Q3NXgwFAYFZ4EFAgMTC2lkOjAwMDcwMDAyMAwGA1UdEwEB/wQCMAAwEAYDVR0lBAkwBwYF"
            "Z4EFCAEwHwYDVR0jBBgwFoAUI/TiKtO+N0pEl3KVSqKDrtdSVy4wDgYDVR0PAQH/BAQDAgUgMCIG"
            "A1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCKMGkGCCsGAQUFBwEBBF0wWzBZBggrBgEF"
            "BQcwAoZNaHR0cHM6Ly93d3cubnV2b3Rvbi5jb20vc2VjdXJpdHkvTlRDLVRQTS1FSy1DZXJ0L051"
            "dm90b24gVFBNIFJvb3QgQ0EgMjExMS5jZXIwCgYIKoZIzj0EAwIDSQAwRgIhAPHOFiBDZd0dfml2"
            "a/KlPFhmX7Ahpd0Wq11ZUW1/ixviAiEAlex8BB5nsR6w8QrANwCxc7fH/YnbjXfMCFiWzeZH7ps="
        )
        self.malformed_cert_der = base64.b64decode(self.malformed_cert_b64)

        # Create a mock certificate for testing
        self.mock_cert = Mock(spec=cryptography.x509.Certificate)
        self.mock_cert.subject = Mock()
        self.mock_cert.subject.__str__ = Mock(return_value="CN=Test Certificate")
        self.mock_cert.public_bytes.return_value = b"mock_der_data"

    def test_init_without_original_bytes(self):
        """Test wrapper initialization without original bytes."""
        wrapper = CertificateWrapper(self.mock_cert)

        # Test through public interface
        self.assertFalse(wrapper.has_original_bytes)
        self.assertIsNone(wrapper.original_bytes)
        # Test delegation works
        self.assertEqual(wrapper.subject, self.mock_cert.subject)

    def test_init_with_original_bytes(self):
        """Test wrapper initialization with original bytes."""
        original_data = b"original_certificate_data"
        wrapper = CertificateWrapper(self.mock_cert, original_data)

        # Test through public interface
        self.assertTrue(wrapper.has_original_bytes)
        self.assertEqual(wrapper.original_bytes, original_data)
        # Test delegation works
        self.assertEqual(wrapper.subject, self.mock_cert.subject)

    def test_getattr_delegation(self):
        """Test that attributes are properly delegated to the wrapped certificate."""
        wrapper = CertificateWrapper(self.mock_cert)

        # Access an attribute that should be delegated
        result = wrapper.subject
        self.assertEqual(result, self.mock_cert.subject)

    def test_public_bytes_der_without_original(self):
        """Test public_bytes DER encoding without original bytes."""
        wrapper = CertificateWrapper(self.mock_cert)

        result = wrapper.public_bytes(Encoding.DER)

        self.mock_cert.public_bytes.assert_called_once_with(Encoding.DER)
        self.assertEqual(result, b"mock_der_data")

    def test_public_bytes_der_with_original(self):
        """Test public_bytes DER encoding with original bytes."""
        original_data = b"original_certificate_data"
        wrapper = CertificateWrapper(self.mock_cert, original_data)

        result = wrapper.public_bytes(Encoding.DER)

        # Should return original bytes, not call the wrapped certificate
        self.mock_cert.public_bytes.assert_not_called()
        self.assertEqual(result, original_data)

    def test_public_bytes_pem_without_original(self):
        """Test public_bytes PEM encoding without original bytes."""
        self.mock_cert.public_bytes.return_value = b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
        wrapper = CertificateWrapper(self.mock_cert)

        result = wrapper.public_bytes(Encoding.PEM)

        self.mock_cert.public_bytes.assert_called_once_with(Encoding.PEM)
        self.assertEqual(result, b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")

    def test_public_bytes_pem_with_original(self):
        """Test public_bytes PEM encoding with original bytes."""
        original_data = self.malformed_cert_der
        wrapper = CertificateWrapper(self.mock_cert, original_data)

        result = wrapper.public_bytes(Encoding.PEM)

        # Should not call the wrapped certificate's method
        self.mock_cert.public_bytes.assert_not_called()

        # Result should be PEM format derived from original bytes
        self.assertIsInstance(result, bytes)
        result_str = result.decode("utf-8")
        self.assertTrue(result_str.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(result_str.endswith("-----END CERTIFICATE-----\n"))

        # Verify that the PEM content can be converted back to the original DER
        pem_lines = result_str.strip().split("\n")
        pem_content = "".join(pem_lines[1:-1])  # Remove headers and join
        recovered_der = base64.b64decode(pem_content)
        self.assertEqual(recovered_der, original_data)

    def test_pem_line_length_compliance(self):
        """Test that PEM output follows RFC 1421 line length requirements (64 chars)."""
        original_data = self.malformed_cert_der
        wrapper = CertificateWrapper(self.mock_cert, original_data)

        result = wrapper.public_bytes(Encoding.PEM)
        result_str = result.decode("utf-8")

        lines = result_str.strip().split("\n")
        # Check that content lines (excluding headers) are max 64 chars
        for line in lines[1:-1]:  # Skip header and footer
            self.assertLessEqual(len(line), 64)

    def test_str_representation(self):
        """Test string representation of the wrapper."""
        wrapper = CertificateWrapper(self.mock_cert)

        result = str(wrapper)

        expected = f"CertificateWrapper(subject={self.mock_cert.subject})"
        self.assertEqual(result, expected)

    def test_repr_representation_without_original(self):
        """Test repr representation without original bytes."""
        wrapper = CertificateWrapper(self.mock_cert)

        result = repr(wrapper)

        expected = f"CertificateWrapper(subject={self.mock_cert.subject}, has_original_bytes=False)"
        self.assertEqual(result, expected)

    def test_repr_representation_with_original(self):
        """Test repr representation with original bytes."""
        original_data = b"original_data"
        wrapper = CertificateWrapper(self.mock_cert, original_data)

        result = repr(wrapper)

        expected = f"CertificateWrapper(subject={self.mock_cert.subject}, has_original_bytes=True)"
        self.assertEqual(result, expected)

    def test_pickling_support(self):
        """Test that the wrapper supports pickling operations."""
        original_data = b"test_data"
        wrapper = CertificateWrapper(self.mock_cert, original_data)

        # Test getstate
        state = wrapper.__getstate__()
        self.assertIsInstance(state, dict)
        self.assertIn("_cert", state)
        self.assertIn("_original_bytes", state)

        # Test setstate
        new_wrapper = CertificateWrapper(Mock(), None)
        new_wrapper.__setstate__(state)
        # Verify state was restored correctly through public interface
        self.assertTrue(new_wrapper.has_original_bytes)
        self.assertEqual(new_wrapper.original_bytes, original_data)

    def test_wrap_certificate_function_without_original(self):
        """Test the wrap_certificate factory function without original bytes."""
        wrapper = wrap_certificate(self.mock_cert)

        self.assertIsInstance(wrapper, CertificateWrapper)
        self.assertFalse(wrapper.has_original_bytes)
        self.assertIsNone(wrapper.original_bytes)

    def test_wrap_certificate_function_with_original(self):
        """Test the wrap_certificate factory function with original bytes."""
        original_data = b"original_certificate_data"
        wrapper = wrap_certificate(self.mock_cert, original_data)

        self.assertIsInstance(wrapper, CertificateWrapper)
        self.assertTrue(wrapper.has_original_bytes)
        self.assertEqual(wrapper.original_bytes, original_data)

    def test_real_malformed_certificate_handling(self):
        """Test with a real malformed certificate that requires pyasn1 re-encoding."""
        # This test simulates the scenario where a malformed certificate is processed

        # Mock the scenario where cryptography fails but pyasn1 succeeds
        mock_reencoded_cert = Mock(spec=cryptography.x509.Certificate)
        mock_reencoded_cert.subject = Mock()
        mock_reencoded_cert.subject.__str__ = Mock(return_value="CN=Nuvoton TPM")

        # Create wrapper as if it came from the certificate loading process
        wrapper = wrap_certificate(mock_reencoded_cert, self.malformed_cert_der)

        # Test that original bytes are preserved
        self.assertTrue(wrapper.has_original_bytes)
        self.assertEqual(wrapper.original_bytes, self.malformed_cert_der)

        # Test DER output uses original bytes
        der_output = wrapper.public_bytes(Encoding.DER)
        self.assertEqual(der_output, self.malformed_cert_der)

        # Test PEM output is derived from original bytes
        pem_output = wrapper.public_bytes(Encoding.PEM)
        self.assertIsInstance(pem_output, bytes)

        # Verify PEM can be converted back to original DER
        pem_str = pem_output.decode("utf-8")
        lines = pem_str.strip().split("\n")
        content = "".join(lines[1:-1])
        recovered_der = base64.b64decode(content)
        self.assertEqual(recovered_der, self.malformed_cert_der)

    def test_unsupported_encoding_fallback(self):
        """Test that unsupported encoding types fall back to wrapped certificate."""
        # Create a custom encoding that's not DER or PEM
        custom_encoding = Mock()
        custom_encoding.name = "CUSTOM"

        original_data = b"original_data"
        wrapper = CertificateWrapper(self.mock_cert, original_data)

        # Should fall back to wrapped certificate for unknown encoding
        wrapper.public_bytes(custom_encoding)
        self.mock_cert.public_bytes.assert_called_once_with(custom_encoding)

    def test_malformed_certificate_cryptography_failure_and_verification(self):
        """
        Comprehensive test demonstrating that the malformed certificate:
        1. Fails to load with python-cryptography
        2. Can be verified with OpenSSL
        3. Is successfully handled by our wrapper after pyasn1 re-encoding
        """
        # Test 1: Demonstrate that python-cryptography fails to load the malformed certificate
        with self.assertRaises(Exception) as context:
            cryptography.x509.load_der_x509_certificate(self.malformed_cert_der)

        # The specific exception type may vary, but it should fail
        self.assertIsInstance(context.exception, Exception)

        # Test 2: Demonstrate that pyasn1 can handle the malformed certificate
        try:
            # Decode and re-encode using pyasn1 (simulating what the Certificate type does)
            pyasn1_cert = pyasn1_decoder.decode(self.malformed_cert_der, asn1Spec=pyasn1_rfc2459.Certificate())[0]
            reencoded_der = pyasn1_encoder.encode(pyasn1_cert)

            # Now cryptography should be able to load the re-encoded certificate
            reencoded_cert = cryptography.x509.load_der_x509_certificate(reencoded_der)
            self.assertIsNotNone(reencoded_cert)

        except Exception as e:
            self.fail(f"pyasn1 should handle the malformed certificate, but got: {e}")

        # Test 3: Verify that our wrapper preserves the original bytes correctly
        wrapper = wrap_certificate(reencoded_cert, self.malformed_cert_der)

        # The wrapper should preserve original bytes
        self.assertTrue(wrapper.has_original_bytes)
        self.assertEqual(wrapper.original_bytes, self.malformed_cert_der)

        # DER output should use original bytes
        der_output = wrapper.public_bytes(Encoding.DER)
        self.assertEqual(der_output, self.malformed_cert_der)

        # PEM output should be derived from original bytes
        pem_output = wrapper.public_bytes(Encoding.PEM)
        pem_str = pem_output.decode("utf-8")

        # Verify PEM format is correct
        self.assertTrue(pem_str.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(pem_str.endswith("-----END CERTIFICATE-----\n"))

        # Test 4: Demonstrate OpenSSL can verify the certificate structure
        # (Even without the root CA, OpenSSL should be able to parse the certificate)
        try:
            with tempfile.NamedTemporaryFile(mode="wb", suffix=".der", delete=False) as temp_file:
                temp_file.write(self.malformed_cert_der)
                temp_file.flush()

                # Use OpenSSL to parse the certificate (should succeed)
                result = subprocess.run(
                    ["openssl", "x509", "-in", temp_file.name, "-inform", "DER", "-text", "-noout"],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                # OpenSSL should successfully parse the certificate
                self.assertEqual(result.returncode, 0)
                self.assertIn("Nuvoton TPM Root CA 2111", result.stdout)
                self.assertIn("Certificate:", result.stdout)

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # Skip if OpenSSL is not available, but don't fail the test
            self.skipTest(f"OpenSSL not available for verification test: {e}")

        # Test 5: Verify certificate details are accessible through wrapper
        # The subject should be empty (as shown in the OpenSSL output)
        self.assertEqual(len(reencoded_cert.subject), 0)

        # The issuer should contain Nuvoton information
        issuer_attrs = {}
        for attr in reencoded_cert.issuer:
            # Use dotted string representation to avoid accessing private _name
            oid_name = attr.oid.dotted_string
            if oid_name == "2.5.4.3":  # Common Name OID
                issuer_attrs["commonName"] = attr.value
        self.assertIn("commonName", issuer_attrs)
        self.assertEqual(issuer_attrs["commonName"], "Nuvoton TPM Root CA 2111")

        # Test 6: Demonstrate that even re-encoded certificates may have parsing issues
        # This shows why preserving original bytes is crucial
        try:
            # Try to access extensions - this may fail due to malformed ASN.1
            extensions = list(reencoded_cert.extensions)
            # If it succeeds, verify it has the expected Subject Alternative Name
            # Subject Alternative Name OID is 2.5.29.17
            has_subject_alt_name = any(ext.oid.dotted_string == "2.5.29.17" for ext in extensions)
            self.assertTrue(has_subject_alt_name, "EK certificate should have Subject Alternative Name extension")
        except (ValueError, Exception) as e:
            # This is actually expected for malformed certificates!
            # Even after pyasn1 re-encoding, some parsing issues may remain
            self.assertIn("parsing asn1", str(e).lower(), f"Expected ASN.1 parsing error, got: {e}")
            # This demonstrates why our wrapper preserves original bytes -
            # they maintain signature validity even when parsing has issues

    def test_certificate_chain_verification_simulation(self):
        """
        Test that simulates certificate chain verification where original bytes matter.
        This demonstrates why preserving original bytes is crucial for signature validation.
        """
        # Create a wrapper with the malformed certificate
        mock_reencoded_cert = Mock(spec=cryptography.x509.Certificate)
        mock_reencoded_cert.subject = Mock()
        mock_reencoded_cert.public_key.return_value = Mock()

        wrapper = wrap_certificate(mock_reencoded_cert, self.malformed_cert_der)

        # Simulate signature verification scenario
        # In real verification, the signature is computed over the exact DER bytes
        original_bytes_for_verification = wrapper.public_bytes(Encoding.DER)

        # Should get the original malformed bytes (preserving signature validity)
        self.assertEqual(original_bytes_for_verification, self.malformed_cert_der)

        # If we didn't preserve original bytes, we'd get re-encoded bytes which would
        # invalidate the signature even though the certificate content is the same
        mock_reencoded_cert.public_bytes.return_value = b"reencoded_different_bytes"

        # Verify that using the wrapper gets original bytes, not re-encoded bytes
        self.assertNotEqual(original_bytes_for_verification, b"reencoded_different_bytes")
        self.assertEqual(original_bytes_for_verification, self.malformed_cert_der)


if __name__ == "__main__":
    unittest.main()
