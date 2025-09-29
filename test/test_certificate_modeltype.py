"""
Unit tests for the Certificate ModelType class.

This module tests the certificate model type functionality including
encoding inference and ASN.1 compliance checking.
"""

import base64
import unittest

import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding

from keylime.certificate_wrapper import CertificateWrapper, wrap_certificate
from keylime.models.base.types.certificate import Certificate


class TestCertificateModelType(unittest.TestCase):
    """Test cases for Certificate ModelType class."""

    def setUp(self):
        """Set up test fixtures."""
        self.cert_type = Certificate()

        # Compliant certificate for testing (loads fine with python-cryptography)
        self.compliant_cert_pem = """-----BEGIN CERTIFICATE-----
MIIClzCCAX+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARUZXN0
MB4XDTI1MDkxMTEyNDU1MVoXDTI2MDkxMTEyNDU1MVowDzENMAsGA1UEAwwEVGVz
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO2V27HsMnKczHCaLgf9
FtxuorvkA5OMkz6KsW1eyryHr0TJ801prLpeNnMZ3U4pqLMqocMc7T2KO6nPZJxO
7zRzehyo9pBBVO4pUR1QMGoTWuJQbqNieDQ4V9dW67N5wp/UWEkK6CNNd6aXjswb
dVaDbIfDL8hMX6Lil3+pTysRWGqjRvBGJxS9r/mYRAvbz1JHPjfegSc0uxnUE+qZ
SrbWa3TN82LX6jw6tKk0Z3CcPJC6QN+ijCxxAoHyLRYUIgZbAKe/FGRbjO0fuW11
L7TcE1k3eaC7RkvotIaCOW/RMOkwKu1MbCzFEA2YRYf9covEwdItzI4FE++ZJrsz
LhUCAwEAaTANBgkqhkiG9w0BAQsFAAOCAQEAeqqJT0LnmAluAjrsCSK/eYYjwjhZ
aKMi/iBO10zfb+GvT4yqEL5gnuWxJEx4TTcDww1clvOC1EcPUZFaKR3GIBGy0ZgJ
zGCfg+sC6liyZ+4PSWSJHD2dT5N3IGp4/hPsrhKnVb9fYbRc0Bc5VHeS9QQoSJDH
f9EbxCcwdErVllRter29OZCb4XnEEbTqLIKRYVrbsu/t4C+vzi0tmKg5HZXf9PMo
D28zJGsCAr8sKW/iUKObqDOHEn56lk12NTJmJmi+g6rEikk/0czJlRjSGnJQLjUg
d4wslruibXBsLPtJw2c6vTC2SV2F1PXwy5j1OKU+D6nxaaItQvWADEjcTg==
-----END CERTIFICATE-----"""

        # Malformed certificate that requires pyasn1 re-encoding (fails with python-cryptography)
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

        # Load certificates for testing
        self.compliant_cert = cryptography.x509.load_pem_x509_certificate(self.compliant_cert_pem.encode())
        self.malformed_cert_der = base64.b64decode(self.malformed_cert_b64)

    def test_infer_encoding_wrapped_certificate(self):
        """Test that CertificateWrapper objects are identified as 'wrapped'."""
        wrapped_cert = wrap_certificate(self.compliant_cert, None)
        encoding = self.cert_type.infer_encoding(wrapped_cert)
        self.assertEqual(encoding, "wrapped")

    def test_infer_encoding_raw_certificate(self):
        """Test that raw cryptography.x509.Certificate objects are identified as 'decoded'."""
        encoding = self.cert_type.infer_encoding(self.compliant_cert)
        self.assertEqual(encoding, "decoded")

    def test_infer_encoding_der_bytes(self):
        """Test that DER bytes are identified as 'der'."""
        der_bytes = self.compliant_cert.public_bytes(Encoding.DER)
        encoding = self.cert_type.infer_encoding(der_bytes)
        self.assertEqual(encoding, "der")

    def test_infer_encoding_pem_string(self):
        """Test that PEM strings are identified as 'pem'."""
        encoding = self.cert_type.infer_encoding(self.compliant_cert_pem)
        self.assertEqual(encoding, "pem")

    def test_infer_encoding_base64_string(self):
        """Test that Base64 strings are identified as 'base64'."""
        encoding = self.cert_type.infer_encoding(self.malformed_cert_b64)
        self.assertEqual(encoding, "base64")

    def test_infer_encoding_none_for_invalid(self):
        """Test that invalid types return None."""
        encoding = self.cert_type.infer_encoding(12345)  # type: ignore[arg-type]  # Testing invalid type
        self.assertIsNone(encoding)

    def test_asn1_compliant_wrapped_without_original_bytes(self):
        """Test that CertificateWrapper without original bytes is ASN.1 compliant."""
        wrapped_cert = wrap_certificate(self.compliant_cert, None)
        compliant = self.cert_type.asn1_compliant(wrapped_cert)
        self.assertTrue(compliant)

    def test_asn1_compliant_wrapped_with_original_bytes(self):
        """Test that CertificateWrapper with original bytes is not ASN.1 compliant."""
        wrapped_cert = wrap_certificate(self.compliant_cert, b"fake_original_bytes")
        compliant = self.cert_type.asn1_compliant(wrapped_cert)
        self.assertFalse(compliant)

    def test_asn1_compliant_raw_certificate(self):
        """Test that raw cryptography.x509.Certificate returns None (already decoded)."""
        compliant = self.cert_type.asn1_compliant(self.compliant_cert)
        self.assertIsNone(compliant)

    def test_asn1_compliant_pem_strings(self):
        """Test ASN.1 compliance checking on PEM strings."""
        # The regular certificate and TPM certificate from test_registrar_db.py are actually ASN.1 compliant
        # and can be loaded directly by python-cryptography without requiring pyasn1 re-encoding
        compliant_regular = self.cert_type.asn1_compliant(self.compliant_cert_pem)
        # Only test one certificate since both are the same type (ASN.1 compliant)

        # Should be ASN.1 compliant (True) since it loads fine with python-cryptography
        self.assertTrue(compliant_regular)

    def test_asn1_compliant_der_and_base64(self):
        """Test ASN.1 compliance checking on DER and Base64 formats."""
        # Test DER bytes - regular certificate should be compliant
        der_bytes = self.compliant_cert.public_bytes(Encoding.DER)
        compliant_der = self.cert_type.asn1_compliant(der_bytes)
        self.assertTrue(compliant_der)

        # Test Base64 string - regular certificate should be compliant
        b64_string = base64.b64encode(der_bytes).decode("utf-8")
        compliant_b64 = self.cert_type.asn1_compliant(b64_string)
        self.assertTrue(compliant_b64)

    def test_asn1_compliant_malformed_certificate(self):
        """Test ASN.1 compliance checking on a truly malformed certificate."""
        # Test the malformed certificate that requires pyasn1 re-encoding
        compliant = self.cert_type.asn1_compliant(self.malformed_cert_b64)
        self.assertFalse(compliant)  # Should be non-compliant since it needs pyasn1 fallback

    def test_asn1_compliant_invalid_data(self):
        """Test that invalid certificate data is not ASN.1 compliant."""
        compliant = self.cert_type.asn1_compliant("invalid_certificate_data")
        self.assertFalse(compliant)

    def test_cast_wrapped_certificate(self):
        """Test that CertificateWrapper objects are returned unchanged."""
        wrapped_cert = wrap_certificate(self.compliant_cert, None)
        result = self.cert_type.cast(wrapped_cert)
        self.assertIs(result, wrapped_cert)

    def test_cast_raw_certificate_to_wrapped(self):
        """Test that raw certificates are wrapped without original bytes."""
        result = self.cert_type.cast(self.compliant_cert)
        self.assertIsInstance(result, CertificateWrapper)
        assert result is not None  # For type checker
        self.assertFalse(result.has_original_bytes)

    def test_cast_pem_strings(self):
        """Test casting PEM strings to CertificateWrapper."""
        # Test regular certificate - should be ASN.1 compliant, no original bytes needed
        result_regular = self.cert_type.cast(self.compliant_cert_pem)
        self.assertIsInstance(result_regular, CertificateWrapper)
        assert result_regular is not None  # For type checker
        self.assertFalse(result_regular.has_original_bytes)

        # Note: Only testing compliant certificate since we now use one consistent certificate for all compliant scenarios

    def test_cast_malformed_certificate(self):
        """Test casting the malformed certificate that requires pyasn1 re-encoding."""
        result = self.cert_type.cast(self.malformed_cert_b64)
        self.assertIsInstance(result, CertificateWrapper)
        assert result is not None  # For type checker
        # Malformed certificate should have original bytes since it needs re-encoding
        self.assertTrue(result.has_original_bytes)

    def test_cast_der_bytes(self):
        """Test casting DER bytes to CertificateWrapper."""
        der_bytes = self.compliant_cert.public_bytes(Encoding.DER)
        result = self.cert_type.cast(der_bytes)
        self.assertIsInstance(result, CertificateWrapper)

    def test_cast_none_value(self):
        """Test that None values return None."""
        result = self.cert_type.cast(None)
        self.assertIsNone(result)

    def test_cast_empty_string(self):
        """Test that empty strings return None."""
        result = self.cert_type.cast("")
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
