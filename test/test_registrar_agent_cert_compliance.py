"""
Integration tests for RegistrarAgent certificate compliance functionality.

This module tests the simplified certificate compliance checking methods
to ensure they work correctly with the new CertificateWrapper-based approach.
"""

import types
import unittest
from unittest.mock import Mock, patch

import cryptography.x509

from keylime.certificate_wrapper import wrap_certificate
from keylime.models.base.types.certificate import Certificate
from keylime.models.registrar.registrar_agent import RegistrarAgent


class TestRegistrarAgentCertCompliance(unittest.TestCase):
    """Test cases for RegistrarAgent certificate compliance methods."""

    # pylint: disable=protected-access,not-callable  # Testing protected methods and dynamic method binding

    def setUp(self):
        """Set up test fixtures."""
        # Create a test certificate
        self.valid_cert_pem = """-----BEGIN CERTIFICATE-----
MIIEnzCCA4egAwIBAgIEMV64bDANBgkqhkiG9w0BAQUFADBtMQswCQYDVQQGEwJE
RTEQMA4GA1UECBMHQmF2YXJpYTEhMB8GA1UEChMYSW5maW5lb24gVGVjaG5vbG9n
aWVzIEFHMQwwCgYDVQQLEwNBSU0xGzAZBgNVBAMTEklGWCBUUE0gRUsgUm9vdCBD
QTAeFw0wNTEwMjAxMzQ3NDNaFw0yNTEwMjAxMzQ3NDNaMHcxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIEwZTYXhvbnkxITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2ll
cyBBRzEMMAoGA1UECxMDQUlNMSYwJAYDVQQDEx1JRlggVFBNIEVLIEludGVybWVk
aWF0ZSBDQSAwMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALftPhYN
t4rE+JnU/XOPICbOBLvfo6iA7nuq7zf4DzsAWBdsZEdFJQfaK331ihG3IpQnlQ2i
YtDim289265f0J4OkPFpKeFU27CsfozVaNUm6UR/uzwA8ncxFc3iZLRMRNLru/Al
VG053ULVDQMVx2iwwbBSAYO9pGiGbk1iMmuZaSErMdb9v0KRUyZM7yABiyDlM3cz
UQX5vLWV0uWqxdGoHwNva5u3ynP9UxPTZWHZOHE6+14rMzpobs6Ww2RR8BgF96rh
4rRAZEl8BXhwiQq4STvUXkfvdpWH4lzsGcDDtrB6Nt3KvVNvsKz+b07Dk+Xzt+EH
NTf3Byk2HlvX+scCAwEAAaOCATswggE3MB0GA1UdDgQWBBQ4k8292HPEIzMV4bE7
qWoNI8wQxzAOBgNVHQ8BAf8EBAMCAgQwEgYDVR0TAQH/BAgwBgEB/wIBADBYBgNV
HSABAf8ETjBMMEoGC2CGSAGG+EUBBy8BMDswOQYIKwYBBQUHAgEWLWh0dHA6Ly93
d3cudmVyaXNpZ24uY29tL3JlcG9zaXRvcnkvaW5kZXguaHRtbDCBlwYDVR0jBIGP
MIGMgBRW65FEhWPWcrOu1EWWC/eUDlRCpqFxpG8wbTELMAkGA1UEBhMCREUxEDAO
BgNVBAgTB0JhdmFyaWExITAfBgNVBAoTGEluZmluZW9uIFRlY2hub2xvZ2llcyBB
RzEMMAoGA1UECxMDQUlNMRswGQYDVQQDExJJRlggVFBNIEVLIFJvb3QgQ0GCAQMw
DQYJKoZIhvcNAQEFBQADggEBABJ1+Ap3rNlxZ0FW0aIgdzktbNHlvXWNxFdYIBbM
OKjmbOos0Y4O60eKPu259XmMItCUmtbzF3oKYXq6ybARUT2Lm+JsseMF5VgikSlU
BJALqpKVjwAds81OtmnIQe2LSu4xcTSavpsL4f52cUAu/maMhtSgN9mq5roYptq9
DnSSDZrX4uYiMPl//rBaNDBflhJ727j8xo9CCohF3yQUoQm7coUgbRMzyO64yMIO
3fhb+Vuc7sNwrMOz3VJN14C3JMoGgXy0c57IP/kD5zGRvljKEvrRC2I147+fPeLS
DueRMS6lblvRKiZgmGAg7YaKOkOaEmVDMQ+fTo2Po7hI5wc=
-----END CERTIFICATE-----"""

        self.valid_cert = cryptography.x509.load_pem_x509_certificate(self.valid_cert_pem.encode())

        # Malformed certificate that actually requires pyasn1 re-encoding
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

        # Create wrapped certificates for testing using Certificate type to ensure proper behavior
        cert_type = Certificate()

        # Create compliant certificate (no original bytes needed)
        self.compliant_wrapped_cert = wrap_certificate(self.valid_cert, None)

        # Create non-compliant certificate using the malformed cert data
        self.non_compliant_wrapped_cert = cert_type.cast(self.malformed_cert_b64)

    def create_mock_registrar_agent(self):
        """Create a mock RegistrarAgent with necessary attributes."""
        agent = Mock()
        agent.changes = {}
        agent.values = {}
        agent._add_error = Mock()

        # Bind the actual methods to the mock instance
        agent._check_cert_compliance = types.MethodType(RegistrarAgent._check_cert_compliance, agent)
        agent._check_all_cert_compliance = types.MethodType(RegistrarAgent._check_all_cert_compliance, agent)

        return agent

    def test_check_cert_compliance_no_new_cert(self):
        """Test _check_cert_compliance when no new certificate is provided."""
        agent = self.create_mock_registrar_agent()
        agent.changes = {}  # No new certificate

        result = agent._check_cert_compliance("ekcert")
        self.assertTrue(result)
        agent._add_error.assert_not_called()

    def test_check_cert_compliance_same_cert(self):
        """Test _check_cert_compliance when new cert is same as old cert."""
        agent = self.create_mock_registrar_agent()
        agent.changes = {"ekcert": self.compliant_wrapped_cert}
        agent.values = {"ekcert": self.compliant_wrapped_cert}

        result = agent._check_cert_compliance("ekcert")
        self.assertTrue(result)
        agent._add_error.assert_not_called()

    def test_check_cert_compliance_different_cert_same_der(self):
        """Test _check_cert_compliance when certificates have same DER bytes."""
        agent = self.create_mock_registrar_agent()
        # Create two different wrapper objects but with same underlying certificate
        cert1 = wrap_certificate(self.valid_cert, None)
        cert2 = wrap_certificate(self.valid_cert, None)

        agent.changes = {"ekcert": cert1}
        agent.values = {"ekcert": cert2}

        result = agent._check_cert_compliance("ekcert")
        self.assertTrue(result)
        agent._add_error.assert_not_called()

    @patch("keylime.config.get")
    def test_check_cert_compliance_compliant_cert(self, mock_config):
        """Test _check_cert_compliance with ASN.1 compliant certificate."""
        mock_config.return_value = "warn"  # Default action

        agent = self.create_mock_registrar_agent()
        agent.changes = {"ekcert": self.compliant_wrapped_cert}
        agent.values = {}  # No old certificate

        result = agent._check_cert_compliance("ekcert")
        self.assertTrue(result)
        agent._add_error.assert_not_called()

    @patch("keylime.config.get")
    def test_check_cert_compliance_non_compliant_cert_warn(self, mock_config):
        """Test _check_cert_compliance with non-compliant certificate (warn mode)."""
        mock_config.return_value = "warn"  # Warn action

        agent = self.create_mock_registrar_agent()
        agent.changes = {"ekcert": self.non_compliant_wrapped_cert}
        agent.values = {}  # No old certificate

        result = agent._check_cert_compliance("ekcert")
        self.assertFalse(result)
        agent._add_error.assert_not_called()  # Should not add error in warn mode

    @patch("keylime.config.get")
    def test_check_cert_compliance_non_compliant_cert_reject(self, mock_config):
        """Test _check_cert_compliance with non-compliant certificate (reject mode)."""
        mock_config.return_value = "reject"  # Reject action

        agent = self.create_mock_registrar_agent()
        agent.changes = {"ekcert": self.non_compliant_wrapped_cert}
        agent.values = {}  # No old certificate

        result = agent._check_cert_compliance("ekcert")
        self.assertFalse(result)
        agent._add_error.assert_called_once()  # Should add error in reject mode

    @patch("keylime.config.get")
    def test_check_all_cert_compliance_no_non_compliant(self, mock_config):
        """Test _check_all_cert_compliance when all certificates are compliant."""
        mock_config.return_value = "warn"

        agent = self.create_mock_registrar_agent()
        agent.changes = {
            "ekcert": self.compliant_wrapped_cert,
            "iak_cert": self.compliant_wrapped_cert,
        }
        agent.values = {}

        # Should not raise any exceptions or log warnings
        with patch("keylime.models.registrar.registrar_agent.logger") as mock_logger:
            agent._check_all_cert_compliance()
            mock_logger.warning.assert_not_called()
            mock_logger.error.assert_not_called()

    @patch("keylime.config.get")
    def test_check_all_cert_compliance_with_non_compliant_warn(self, mock_config):
        """Test _check_all_cert_compliance with non-compliant certificates (warn mode)."""
        mock_config.return_value = "warn"

        agent = self.create_mock_registrar_agent()
        agent.changes = {
            "ekcert": self.non_compliant_wrapped_cert,
            "iak_cert": self.compliant_wrapped_cert,
            "idevid_cert": self.non_compliant_wrapped_cert,
        }
        agent.values = {}

        with patch("keylime.models.registrar.registrar_agent.logger") as mock_logger:
            agent._check_all_cert_compliance()
            # Should log warning for non-compliant certificates
            mock_logger.warning.assert_called_once()
            format_string = mock_logger.warning.call_args[0][0]
            cert_names = mock_logger.warning.call_args[0][1]
            self.assertIn("Certificate(s) %s may not conform", format_string)
            self.assertEqual("'ekcert' and 'idevid_cert'", cert_names)

    @patch("keylime.config.get")
    def test_check_all_cert_compliance_with_non_compliant_reject(self, mock_config):
        """Test _check_all_cert_compliance with non-compliant certificates (reject mode)."""
        mock_config.return_value = "reject"

        agent = self.create_mock_registrar_agent()
        agent.changes = {
            "ekcert": self.non_compliant_wrapped_cert,
            "mtls_cert": self.non_compliant_wrapped_cert,
        }
        agent.values = {}

        with patch("keylime.models.registrar.registrar_agent.logger") as mock_logger:
            agent._check_all_cert_compliance()
            # Should log error for non-compliant certificates
            mock_logger.error.assert_called_once()
            format_string = mock_logger.error.call_args[0][0]
            cert_names = mock_logger.error.call_args[0][1]
            self.assertIn("Certificate(s) %s may not conform", format_string)
            self.assertIn("were rejected due to config", format_string)
            self.assertEqual("'ekcert' and 'mtls_cert'", cert_names)

    @patch("keylime.config.get")
    def test_check_all_cert_compliance_ignore_mode(self, mock_config):
        """Test _check_all_cert_compliance with ignore mode."""
        mock_config.return_value = "ignore"

        agent = self.create_mock_registrar_agent()
        agent.changes = {
            "ekcert": self.non_compliant_wrapped_cert,
            "iak_cert": self.non_compliant_wrapped_cert,
        }
        agent.values = {}

        with patch("keylime.models.registrar.registrar_agent.logger") as mock_logger:
            agent._check_all_cert_compliance()
            # Should not log anything in ignore mode
            mock_logger.warning.assert_not_called()
            mock_logger.error.assert_not_called()

    def test_check_all_cert_compliance_single_non_compliant(self):
        """Test _check_all_cert_compliance message formatting for single certificate."""
        agent = self.create_mock_registrar_agent()
        agent.changes = {"ekcert": self.non_compliant_wrapped_cert}
        agent.values = {}

        with patch("keylime.config.get", return_value="warn"):
            with patch("keylime.models.registrar.registrar_agent.logger") as mock_logger:
                agent._check_all_cert_compliance()
                # Should format message correctly for single certificate
                format_string = mock_logger.warning.call_args[0][0]
                cert_names = mock_logger.warning.call_args[0][1]
                self.assertIn("Certificate(s) %s may not conform", format_string)
                self.assertEqual("'ekcert'", cert_names)
                self.assertNotIn(" and", cert_names)  # Should not have "and" for single cert

    def test_field_names_coverage(self):
        """Test that all expected certificate field names are checked."""
        agent = self.create_mock_registrar_agent()
        agent.changes = {
            "ekcert": self.non_compliant_wrapped_cert,
            "iak_cert": self.non_compliant_wrapped_cert,
            "idevid_cert": self.non_compliant_wrapped_cert,
            "mtls_cert": self.non_compliant_wrapped_cert,
        }
        agent.values = {}

        with patch("keylime.config.get", return_value="warn"):
            with patch("keylime.models.registrar.registrar_agent.logger") as mock_logger:
                agent._check_all_cert_compliance()
                # Should check all four certificate fields
                format_string = mock_logger.warning.call_args[0][0]
                cert_names = mock_logger.warning.call_args[0][1]
                self.assertIn("Certificate(s) %s may not conform", format_string)
                expected_names = "'ekcert', 'iak_cert', 'idevid_cert' and 'mtls_cert'"
                self.assertEqual(expected_names, cert_names)


if __name__ == "__main__":
    unittest.main()
