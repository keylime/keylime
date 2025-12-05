"""
Unit tests for RegistrarAgent TPM identity immutability security check.

This module tests the _check_tpm_identity_immutable() method which prevents
UUID spoofing attacks by rejecting re-registration attempts with different TPM identities.
"""

import base64
import types
import unittest
from unittest.mock import Mock

import cryptography.x509

from keylime.certificate_wrapper import wrap_certificate
from keylime.models.registrar.registrar_agent import RegistrarAgent


class TestRegistrarAgentTPMIdentity(unittest.TestCase):
    """Test cases for RegistrarAgent TPM identity immutability."""

    # pylint: disable=protected-access  # Testing protected methods
    # pylint: disable=not-callable  # False positive: methods bound via types.MethodType are callable

    def setUp(self):
        """Set up test fixtures."""
        # EK certificate (used for testing certificate comparison)
        self.ek_cert_pem = """-----BEGIN CERTIFICATE-----
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

        # Create wrapped cert from real certificate
        self.ek_cert = cryptography.x509.load_pem_x509_certificate(self.ek_cert_pem.encode())
        self.ek_cert_wrapped = wrap_certificate(self.ek_cert, None)

        # Create a different cert mock that returns different DER bytes
        self.different_ek_cert_wrapped = Mock()
        self.different_ek_cert_wrapped.public_bytes = Mock(return_value=b"DIFFERENT_CERTIFICATE_DER_BYTES_FOR_TESTING")

        # Sample TPM keys (base64 encoded for simplicity in tests)
        self.ek_tpm_1 = b"EK_TPM_KEY_NUMBER_ONE_SAMPLE_DATA"
        self.ek_tpm_2 = b"EK_TPM_KEY_NUMBER_TWO_DIFFERENT_"
        self.aik_tpm_1 = b"AIK_TPM_KEY_NUMBER_ONE_SAMPLE_DATA"
        self.aik_tpm_2 = b"AIK_TPM_KEY_NUMBER_TWO_DIFFERENT_"

        # IAK/IDevID keys for testing that they are not checked
        self.iak_tpm_1 = b"IAK_TPM_KEY_NUMBER_ONE"
        self.iak_tpm_2 = b"IAK_TPM_KEY_NUMBER_TWO"

    def create_mock_registrar_agent(self, agent_id="test-agent-uuid"):
        """Create a mock RegistrarAgent with necessary attributes."""
        agent = Mock()
        agent.agent_id = agent_id
        agent.changes = {}
        agent.values = {}
        agent.committed = {}
        agent._add_error = Mock()
        agent.errors = {}

        # Bind the actual method to the mock instance
        agent._check_tpm_identity_immutable = types.MethodType(RegistrarAgent._check_tpm_identity_immutable, agent)

        return agent

    def test_new_agent_no_committed_values(self):
        """Test that new agents (no committed values) are not checked."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {}  # New agent, no previous values
        agent.changes = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }

        agent._check_tpm_identity_immutable()

        # Should not add any errors for new agents
        agent._add_error.assert_not_called()

    def test_reregistration_same_tpm_all_fields_identical(self):
        """Test re-registration with identical TPM identity passes."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }
        agent.changes = {
            "ek_tpm": self.ek_tpm_1,  # Same
            "ekcert": self.ek_cert_wrapped,  # Same
            "aik_tpm": self.aik_tpm_1,  # Same
        }

        agent._check_tpm_identity_immutable()

        # Should not add any errors
        agent._add_error.assert_not_called()

    def test_reregistration_different_ek_tpm(self):
        """Test re-registration with different EK TPM is rejected."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }
        agent.changes = {
            "ek_tpm": self.ek_tpm_2,  # DIFFERENT
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }

        agent._check_tpm_identity_immutable()

        # Should add error for agent_id field
        agent._add_error.assert_called_once()
        call_args = agent._add_error.call_args
        self.assertEqual(call_args[0][0], "agent_id")
        self.assertIn("different TPM identity", call_args[0][1])
        self.assertIn("ek_tpm", call_args[0][1])

    def test_reregistration_different_aik_tpm(self):
        """Test re-registration with different AIK TPM is rejected."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }
        agent.changes = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_2,  # DIFFERENT
        }

        agent._check_tpm_identity_immutable()

        # Should add error for agent_id field
        agent._add_error.assert_called_once()
        call_args = agent._add_error.call_args
        self.assertEqual(call_args[0][0], "agent_id")
        self.assertIn("different TPM identity", call_args[0][1])
        self.assertIn("aik_tpm", call_args[0][1])

    def test_reregistration_different_ekcert(self):
        """Test re-registration with different EK certificate is rejected."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }
        agent.changes = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.different_ek_cert_wrapped,  # DIFFERENT
            "aik_tpm": self.aik_tpm_1,
        }

        agent._check_tpm_identity_immutable()

        # Should add error for agent_id field
        agent._add_error.assert_called_once()
        call_args = agent._add_error.call_args
        self.assertEqual(call_args[0][0], "agent_id")
        self.assertIn("different TPM identity", call_args[0][1])
        self.assertIn("ekcert", call_args[0][1])

    def test_reregistration_multiple_fields_changed(self):
        """Test re-registration with multiple fields changed lists all of them."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }
        agent.changes = {
            "ek_tpm": self.ek_tpm_2,  # DIFFERENT
            "ekcert": self.different_ek_cert_wrapped,  # DIFFERENT
            "aik_tpm": self.aik_tpm_2,  # DIFFERENT
        }

        agent._check_tpm_identity_immutable()

        # Should add error listing all changed fields
        agent._add_error.assert_called_once()
        call_args = agent._add_error.call_args
        self.assertEqual(call_args[0][0], "agent_id")
        error_message = call_args[0][1]
        self.assertIn("ek_tpm", error_message)
        self.assertIn("ekcert", error_message)
        self.assertIn("aik_tpm", error_message)

    def test_adding_ekcert_to_existing_agent(self):
        """Test that adding EK cert to existing agent (without cert) is allowed."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": None,  # Previously no cert
            "aik_tpm": self.aik_tpm_1,
        }
        agent.changes = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,  # NOW adding cert
            "aik_tpm": self.aik_tpm_1,
        }

        agent._check_tpm_identity_immutable()

        # Should not add any errors - adding cert is allowed
        agent._add_error.assert_not_called()

    def test_removing_ek_tpm_rejected(self):
        """Test that removing an existing EK TPM is rejected."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }
        agent.changes = {
            "ek_tpm": None,  # Trying to remove
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }

        agent._check_tpm_identity_immutable()

        # Should add error
        agent._add_error.assert_called_once()
        call_args = agent._add_error.call_args
        self.assertIn("ek_tpm", call_args[0][1])

    def test_iak_idevid_changes_not_checked(self):
        """Test that IAK/IDevID field changes are NOT checked (allowed)."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
            "iak_tpm": self.iak_tpm_1,
            "idevid_tpm": b"IDEVID_OLD",
        }
        agent.changes = {
            "ek_tpm": self.ek_tpm_1,  # Same
            "ekcert": self.ek_cert_wrapped,  # Same
            "aik_tpm": self.aik_tpm_1,  # Same
            "iak_tpm": self.iak_tpm_2,  # DIFFERENT - but not checked
            "idevid_tpm": b"IDEVID_NEW",  # DIFFERENT - but not checked
        }

        agent._check_tpm_identity_immutable()

        # Should not add any errors - IAK/IDevID are not checked
        agent._add_error.assert_not_called()

    def test_only_changed_fields_are_checked(self):
        """Test that only fields in changes dict are checked."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }
        # Only updating IP, not touching TPM identity fields
        agent.changes = {
            "ip": "192.168.1.100",
        }

        agent._check_tpm_identity_immutable()

        # Should not add any errors - no identity fields changed
        agent._add_error.assert_not_called()

    def test_base64_encoded_tpm_keys(self):
        """Test that base64-encoded TPM keys are properly compared."""
        agent = self.create_mock_registrar_agent()

        # Simulate keys stored as base64 strings (as they might be from database)
        ek_b64 = base64.b64encode(self.ek_tpm_1).decode("utf-8")
        aik_b64 = base64.b64encode(self.aik_tpm_1).decode("utf-8")

        agent.committed = {
            "ek_tpm": self.ek_tpm_1,  # As bytes
            "aik_tpm": self.aik_tpm_1,  # As bytes
        }
        agent.changes = {
            "ek_tpm": ek_b64,  # As base64 string
            "aik_tpm": aik_b64,  # As base64 string
        }

        agent._check_tpm_identity_immutable()

        # Should not add any errors - should handle both formats
        agent._add_error.assert_not_called()

    def test_partial_update_only_one_field(self):
        """Test updating only one TPM field while others remain unchanged."""
        agent = self.create_mock_registrar_agent()
        agent.committed = {
            "ek_tpm": self.ek_tpm_1,
            "ekcert": self.ek_cert_wrapped,
            "aik_tpm": self.aik_tpm_1,
        }
        # Only changing AIK in this update
        agent.changes = {
            "aik_tpm": self.aik_tpm_2,  # DIFFERENT
        }

        agent._check_tpm_identity_immutable()

        # Should add error for the changed field
        agent._add_error.assert_called_once()
        call_args = agent._add_error.call_args
        self.assertIn("aik_tpm", call_args[0][1])


if __name__ == "__main__":
    unittest.main()
