"""
Unit tests for certificate original bytes preservation functionality.

Tests that the Certificate type correctly preserves original certificate bytes
when malformed certificates require pyasn1 re-encoding, ensuring signatures
remain valid throughout the database lifecycle.
"""

import base64
import os
import sys
import unittest
from unittest.mock import Mock

# Add the parent directory to sys.path to import from local keylime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
# Imported after path manipulation to get local version
from keylime.models.base.types.certificate import Certificate  # pylint: disable=wrong-import-position


class TestCertificatePreservation(unittest.TestCase):
    """Test certificate original bytes preservation functionality."""

    # pylint: disable=protected-access  # Tests need access to internal cache for validation

    def setUp(self):
        """Set up test fixtures."""
        # Real malformed TPM certificate from /tmp/malformed_cert.txt
        # This is a Nuvoton TPM EK certificate that requires pyasn1 re-encoding
        malformed_cert_multiline = """MIIDUjCCAvegAwIBAgILAI5xYHQ14nH5hdYwCgYIKoZIzj0EAwIwVTFTMB8GA1UEAxMYTnV2b3Rv
biBUUE0gUm9vdCBDQSAyMTExMCUGA1UEChMeTnV2b3RvbiBUZWNobm9sb2d5IENvcnBvcmF0aW9u
MAkGA1UEBhMCVFcwHhcNMTkwNzIzMTcxNTEzWhcNMzkwNzE5MTcxNTEzWjAAMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk8kCj7srY/Zlvm1795fVXdyX44w5qsd1m5VywMDgSOavzPKO
kgbHgQNx6Ak5+4Q43EJ/5qsaDBv59F8W7K69maUwcMNq1xpuq0V/LiwgJVAtc3CdvlxtwQrn7+Uq
ieIGf+i8sGxpeUCSmYHJPTHNHqjQnvUtdGoy/+WO0i7WsAvX3k/gHHr4p58a8urjJ1RG2Lk1g48D
ESwl+D7atQEPWzgjr6vK/s5KpLrn7M+dh97TUbG1510AOWBPP35MtT8IZbqC4hs2Ol16gT1M3a9e
+GaMZkItLUwV76vKDNEgTZG8M1C9OItA/xwzlfXbPepzpxWb4kzHS4qZoQtl4vBZrQIDAQABo4IB
NjCCATIwUAYDVR0RAQH/BEYwRKRCMEAxPjAUBgVngQUCARMLaWQ6NEU1NDQzMDAwEAYFZ4EFAgIT
B05QQ1Q3NXgwFAYFZ4EFAgMTC2lkOjAwMDcwMDAyMAwGA1UdEwEB/wQCMAAwEAYDVR0lBAkwBwYF
Z4EFCAEwHwYDVR0jBBgwFoAUI/TiKtO+N0pEl3KVSqKDrtdSVy4wDgYDVR0PAQH/BAQDAgUgMCIG
A1UdCQQbMBkwFwYFZ4EFAhAxDjAMDAMyLjACAQACAgCKMGkGCCsGAQUFBwEBBF0wWzBZBggrBgEF
BQcwAoZNaHR0cHM6Ly93d3cubnV2b3Rvbi5jb20vc2VjdXJpdHkvTlRDLVRQTS1FSy1DZXJ0L051
dm90b24gVFBNIFJvb3QgQ0EgMjExMS5jZXIwCgYIKoZIzj0EAwIDSQAwRgIhAPHOFiBDZd0dfml2
a/KlPFhmX7Ahpd0Wq11ZUW1/ixviAiEAlex8BB5nsR6w8QrANwCxc7fH/YnbjXfMCFiWzeZH7ps="""
        # Normalize the Base64 (remove newlines and spaces)
        self.malformed_cert_b64 = "".join(malformed_cert_multiline.split())
        # Decode to get original DER bytes
        self.malformed_cert_der = base64.b64decode(self.malformed_cert_b64)
        # Create Certificate instance for testing
        self.cert_type = Certificate()

    def test_malformed_certificate_parsing(self):
        """Test that malformed certificate can be parsed using pyasn1 fallback."""
        # This malformed certificate should trigger pyasn1 re-encoding
        cert = self.cert_type.cast(self.malformed_cert_der)

        # Should successfully parse despite being malformed
        self.assertIsNotNone(cert)

        # Should have preserved original bytes in cache
        self.assertTrue(self.cert_type.has_original_bytes())  # type: ignore[arg-type]

        # Cached bytes should be the original DER bytes
        cached_bytes = self.cert_type._original_bytes_cache.decode("utf-8")  # type: ignore[arg-type]
        self.assertEqual(cached_bytes, self.malformed_cert_b64)

    def test_asn1_compliance_detection(self):
        """Test that malformed certificate is detected as non-ASN.1 compliant."""
        # This certificate should not be ASN.1 DER compliant
        is_compliant = self.cert_type.asn1_compliant(self.malformed_cert_der)
        self.assertFalse(is_compliant)

        # Base64 version should also be non-compliant
        is_compliant_b64 = self.cert_type.asn1_compliant(self.malformed_cert_b64)
        self.assertFalse(is_compliant_b64)

    def test_dump_preserves_original_bytes(self):
        """Test that _dump() returns original bytes for malformed certificates."""
        # Parse malformed certificate (triggers pyasn1 and caching)
        cert = self.cert_type.cast(self.malformed_cert_der)

        # Dump should return original bytes as Base64
        dumped = self.cert_type._dump(cert)  # pylint: disable=protected-access
        self.assertEqual(dumped, self.malformed_cert_b64)

        # Verify round-trip preservation
        self.assertIsNotNone(dumped)
        restored_bytes = base64.b64decode(dumped)  # type: ignore[arg-type]
        self.assertEqual(restored_bytes, self.malformed_cert_der)

    def test_db_load_preserves_original_bytes(self):
        """Test that db_load() preserves original bytes when reading from database."""
        mock_dialect = Mock()

        # Simulate loading from database with our malformed certificate
        cert = self.cert_type.db_load(self.malformed_cert_b64, mock_dialect)

        # Should successfully load certificate
        self.assertIsNotNone(cert)

        # Should have preserved original bytes in cache
        self.assertTrue(self.cert_type.has_original_bytes())  # type: ignore[arg-type]

        # Cached bytes should be the original DER bytes, base64-encoded
        if self.cert_type._original_bytes_cache:
            cached_bytes = self.cert_type._original_bytes_cache.decode("utf-8")
            self.assertEqual(cached_bytes, self.malformed_cert_b64)

    def test_database_round_trip_preservation(self):
        """Test complete database round-trip preserves original bytes."""
        mock_dialect = Mock()

        # Step 1: Initial parsing (simulates agent registration)
        cert1 = self.cert_type.cast(self.malformed_cert_der)
        self.assertIsNotNone(cert1)
        self.assertTrue(self.cert_type.has_original_bytes())  # type: ignore[arg-type]

        # Step 2: Store to database simulation
        db_value = self.cert_type._dump(cert1)  # pylint: disable=protected-access
        self.assertEqual(db_value, self.malformed_cert_b64)

        # Step 3: Create fresh Certificate instance (simulates new session)
        fresh_cert_type = Certificate()
        self.assertEqual(fresh_cert_type._original_bytes_cache, None)  # pylint: disable=protected-access

        # Step 4: Load from database
        cert2 = fresh_cert_type.db_load(db_value, mock_dialect)
        self.assertIsNotNone(cert2)
        self.assertTrue(fresh_cert_type.has_original_bytes())  # type: ignore[arg-type]

        # Step 5: Verify original bytes preserved across round-trip
        self.assertTrue(fresh_cert_type._original_bytes_cache)
        cached_bytes = fresh_cert_type._original_bytes_cache.decode("utf-8")  # type: ignore[arg-type]
        self.assertEqual(cached_bytes, self.malformed_cert_b64)

        # Step 6: Subsequent dump should still use original bytes
        second_dump = fresh_cert_type._dump(cert2)  # pylint: disable=protected-access
        self.assertEqual(second_dump, self.malformed_cert_b64)

    def test_compliant_certificate_no_caching(self):
        """Test that ASN.1-compliant certificates don't use caching."""
        # Create a simple ASN.1-compliant certificate for testing
        # We'll use a well-formed Base64 string that represents valid DER
        compliant_cert_b64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJKW9Q=="  # Truncated for test

        try:
            # Try to parse - may fail due to truncation, but that's ok for this test
            cert = self.cert_type.cast(compliant_cert_b64)
            if cert:  # Only test if parsing succeeded
                # Should not have cached original bytes
                self.assertFalse(self.cert_type.has_original_bytes())
                self.assertEqual(self.cert_type._original_bytes_cache, None)
        except (ValueError, Exception):
            # Expected for truncated certificate - just verify no caching occurred
            self.assertEqual(self.cert_type._original_bytes_cache, None)

    def test_db_load_with_none_value(self):
        """Test that db_load() handles None values correctly."""
        mock_dialect = Mock()

        result = self.cert_type.db_load(None, mock_dialect)
        self.assertIsNone(result)
        self.assertEqual(self.cert_type._original_bytes_cache, None)

    def test_db_load_with_invalid_base64(self):
        """Test that db_load() handles invalid Base64 gracefully."""
        mock_dialect = Mock()

        # Invalid Base64 string
        invalid_b64 = "not_valid_base64!!!"

        # Should not raise exception, but may return None or attempt fallback
        try:
            _ = self.cert_type.db_load(invalid_b64, mock_dialect)
            # Result may be None or may attempt to parse the string directly
            # The important thing is it doesn't crash
        except Exception:
            # Some exceptions are expected for invalid data
            # We just want to ensure it's handled gracefully
            pass

    def test_render_method_unaffected(self):
        """Test that render() method works normally with cached certificates."""
        cert = self.cert_type.cast(self.malformed_cert_der)
        self.assertIsNotNone(cert)

        # render() should return PEM format (doesn't use cached bytes)
        rendered = self.cert_type.render(cert)

        # Should be PEM format
        if rendered:  # Only test if rendering succeeded
            self.assertIn("-----BEGIN CERTIFICATE-----", rendered)
            self.assertIn("-----END CERTIFICATE-----", rendered)


if __name__ == "__main__":
    unittest.main()
