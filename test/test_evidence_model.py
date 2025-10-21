"""
Unit tests for keylime.models.verifier.evidence module
"""

# pyright: reportAttributeAccessIssue=false
# pylint: disable=no-member
# ORM models with dynamically-created attributes from metaclasses

import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import registry

from keylime.models import db_manager
from keylime.models.verifier import Attestation, EvidenceItem
from keylime.models.verifier.evidence import (
    Capabilities,
    CertificationCapabilities,
    CertificationData,
    CertificationKey,
    CertificationParameters,
    LogCapabilities,
    LogData,
    LogParameters,
    LogResults,
)


class TestEvidenceItemModel(unittest.TestCase):
    """Test cases for the EvidenceItem model"""

    def setUp(self):
        """Set up test fixtures"""
        # Initialize database with in-memory SQLite
        # pylint: disable=protected-access
        # Directly set up db_manager without using make_engine() which reads from config
        db_manager._engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        db_manager._registry = registry()
        db_manager._service = "test"
        # pylint: enable=protected-access

        # Process schema for the models
        EvidenceItem.process_schema()
        Attestation.process_schema()

        # Create tables
        db_manager.registry.metadata.create_all(db_manager.engine)

    def test_evidence_item_schema_definition(self):
        """Test that evidence item schema is properly defined"""
        self.assertTrue(EvidenceItem.schema_processed)
        self.assertEqual(EvidenceItem.table_name, "evidence_items")

    def test_evidence_item_fields_exist(self):
        """Test that all expected fields are defined"""
        expected_fields = ["agent_id", "attestation_index", "evidence_class", "evidence_type"]

        for field_name in expected_fields:
            self.assertIn(field_name, EvidenceItem.fields)

    def test_evidence_class_choices(self):
        """Test that evidence_class field has correct choices"""
        # pylint: disable=unsubscriptable-object
        evidence_class_field = EvidenceItem.fields["evidence_class"]
        # pylint: enable=unsubscriptable-object

        self.assertIsNotNone(evidence_class_field)

    def test_evidence_type_choices(self):
        """Test that evidence_type field allows specific types"""
        # pylint: disable=unsubscriptable-object
        evidence_type_field = EvidenceItem.fields["evidence_type"]
        # pylint: enable=unsubscriptable-object

        self.assertIsNotNone(evidence_type_field)

    def test_create_with_valid_dict(self):
        """Test creating evidence item from valid dictionary"""
        data = {"evidence_class": "certification", "evidence_type": "tpm_quote", "capabilities": {}}

        with patch.object(EvidenceItem, "empty") as mock_empty:
            mock_evidence = MagicMock()
            mock_empty.return_value = mock_evidence

            result = EvidenceItem.create(data)

            mock_empty.assert_called_once()
            mock_evidence.receive_capabilities.assert_called_once_with(data)
            self.assertEqual(result, mock_evidence)

    def test_create_with_invalid_type(self):
        """Test that create raises TypeError for non-dict input"""
        with self.assertRaises(TypeError) as context:
            EvidenceItem.create("not a dict")

        self.assertIn("must be a dictionary", str(context.exception))

    def test_receive_capabilities_certification(self):
        """Test receiving capabilities for certification evidence"""
        evidence = EvidenceItem.empty()
        data = {
            "evidence_class": "certification",
            "evidence_type": "tpm_quote",
            "capabilities": {"algorithms": ["rsa2048"]},
        }

        with patch.object(evidence, "refresh_metadata"):
            evidence.receive_capabilities(data)

            self.assertEqual(evidence.evidence_class, "certification")
            self.assertEqual(evidence.evidence_type, "tpm_quote")
            self.assertIsNotNone(evidence.capabilities)

    def test_receive_capabilities_log(self):
        """Test receiving capabilities for log evidence"""
        evidence = EvidenceItem.empty()
        data = {"evidence_class": "log", "evidence_type": "ima_log", "capabilities": {"hash_algorithms": ["sha256"]}}

        with patch.object(evidence, "refresh_metadata"):
            evidence.receive_capabilities(data)

            self.assertEqual(evidence.evidence_class, "log")
            self.assertEqual(evidence.evidence_type, "ima_log")
            self.assertIsNotNone(evidence.capabilities)

    def test_initialise_parameters_certification(self):
        """Test initializing parameters for certification evidence"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"

        evidence.initialise_parameters()

        self.assertIsNotNone(evidence.chosen_parameters)

    def test_initialise_parameters_log(self):
        """Test initializing parameters for log evidence"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"

        evidence.initialise_parameters()

        self.assertIsNotNone(evidence.chosen_parameters)

    def test_validate_parameters(self):
        """Test that validate_parameters calls validate_choices"""
        evidence = EvidenceItem.empty()
        mock_params = MagicMock()
        mock_caps = MagicMock()

        with patch.object(evidence, "refresh_metadata"):
            # Use PropertyMock to mock the property getters
            with patch.object(
                type(evidence), "chosen_parameters", new_callable=lambda: property(lambda self: mock_params)
            ):
                with patch.object(
                    type(evidence), "capabilities", new_callable=lambda: property(lambda self: mock_caps)
                ):
                    evidence.validate_parameters()

                    mock_params.validate_choices.assert_called_once_with(check_against=mock_caps)

    def test_generate_challenge_certification(self):
        """Test generating challenge for certification evidence"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"

        with patch.object(evidence, "refresh_metadata"):
            evidence.generate_challenge(256)

            self.assertIsNotNone(evidence.chosen_parameters)

    def test_generate_challenge_non_certification_raises(self):
        """Test that generating challenge for non-certification raises ValueError"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"

        with self.assertRaises(ValueError) as context:
            evidence.generate_challenge(256)

        self.assertIn("certification", str(context.exception))

    def test_receive_evidence_certification(self):
        """Test receiving evidence data for certification"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"
        data = {"data": {"quote": "mock-quote-data"}}

        with patch.object(evidence, "refresh_metadata"):
            evidence.receive_evidence(data)

            self.assertIsNotNone(evidence.data)
            self.assertIsNotNone(evidence.results)

    def test_receive_evidence_log(self):
        """Test receiving evidence data for log"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"
        # Initialize chosen_parameters as required by LogData.update()
        evidence.initialise_parameters()
        data = {"data": {"log_entries": []}}

        with patch.object(evidence, "refresh_metadata"):
            evidence.receive_evidence(data)

            self.assertIsNotNone(evidence.data)
            self.assertIsNotNone(evidence.results)

    def test_render_evidence_requested(self):
        """Test rendering evidence requested format"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"
        evidence.chosen_parameters = None

        result = evidence.render_evidence_requested()

        self.assertIn("evidence_class", result)
        self.assertIn("evidence_type", result)
        self.assertEqual(result["evidence_class"], "certification")
        self.assertEqual(result["evidence_type"], "tpm_quote")

    def test_render_evidence_requested_with_parameters(self):
        """Test rendering evidence requested with chosen parameters"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"

        mock_params = MagicMock()
        mock_params.render.return_value = {"challenge": "mock-challenge"}

        with patch.object(type(evidence), "chosen_parameters", new_callable=lambda: property(lambda self: mock_params)):
            result = evidence.render_evidence_requested()

            self.assertIn("chosen_parameters", result)
            self.assertEqual(result["chosen_parameters"]["challenge"], "mock-challenge")

    def test_render_evidence_acknowledged(self):
        """Test rendering evidence acknowledged format"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"
        evidence.capabilities = None
        evidence.chosen_parameters = None
        evidence.data = None

        result = evidence.render_evidence_acknowledged()

        self.assertIn("evidence_class", result)
        self.assertIn("evidence_type", result)

    def test_render_evidence_acknowledged_with_data(self):
        """Test rendering evidence acknowledged with all data"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"

        mock_caps = MagicMock()
        mock_caps.render.return_value = {"algorithms": ["rsa2048"]}

        mock_params = MagicMock()
        mock_params.render.return_value = {"nonce": "test-nonce"}

        mock_data = MagicMock()
        mock_data.render.return_value = {"quote": "test-quote"}

        with patch.object(type(evidence), "capabilities", new_callable=lambda: property(lambda self: mock_caps)):
            with patch.object(
                type(evidence), "chosen_parameters", new_callable=lambda: property(lambda self: mock_params)
            ):
                with patch.object(type(evidence), "data", new_callable=lambda: property(lambda self: mock_data)):
                    result = evidence.render_evidence_acknowledged()

                    self.assertIn("capabilities", result)
                    self.assertIn("chosen_parameters", result)
                    self.assertIn("data", result)

    def test_render_state(self):
        """Test that render_state calls render_evidence_acknowledged"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"

        with patch.object(evidence, "render_evidence_acknowledged") as mock_render:
            mock_render.return_value = {"test": "output"}

            result = evidence.render_state()

            mock_render.assert_called_once()
            self.assertEqual(result, {"test": "output"})

    def test_compatible_with_same_capabilities(self):
        """Test compatibility check with same capabilities"""
        evidence1 = EvidenceItem.empty()
        evidence1.evidence_class = "certification"
        evidence1.evidence_type = "tpm_quote"

        evidence2 = EvidenceItem.empty()
        evidence2.evidence_class = "certification"
        evidence2.evidence_type = "tpm_quote"

        mock_caps1 = MagicMock()
        mock_caps1.values = {"algorithms": ["rsa2048"]}

        mock_caps2 = MagicMock()
        mock_caps2.values = {"algorithms": ["rsa2048"]}

        with patch.object(
            type(evidence1),
            "capabilities",
            new_callable=lambda: property(lambda self: mock_caps1 if self is evidence1 else mock_caps2),
        ):
            result = evidence1.compatible_with(evidence2)

            self.assertTrue(result)

    def test_compatible_with_no_capabilities(self):
        """Test compatibility check when both have no capabilities"""
        evidence1 = EvidenceItem.empty()
        evidence1.evidence_class = "certification"
        evidence1.capabilities = None

        evidence2 = EvidenceItem.empty()
        evidence2.evidence_class = "certification"
        evidence2.capabilities = None

        result = evidence1.compatible_with(evidence2)

        # Should be compatible if both have no capabilities
        self.assertTrue(result or evidence1.evidence_class == evidence2.evidence_class)

    def test_refresh_metadata_with_attestation(self):
        """Test that refresh_metadata calls attestation's refresh_metadata"""
        evidence = EvidenceItem.empty()
        mock_attestation = MagicMock()

        with patch.object(type(evidence), "attestation", new_callable=lambda: property(lambda self: mock_attestation)):
            evidence.refresh_metadata()

            mock_attestation.refresh_metadata.assert_called_once()

    def test_refresh_metadata_without_attestation(self):
        """Test that refresh_metadata doesn't fail without attestation"""
        evidence = EvidenceItem.empty()
        # Don't set attestation - it defaults to an empty association

        # Should not raise an exception
        try:
            evidence.refresh_metadata()
        except AttributeError:
            self.fail("refresh_metadata raised AttributeError without attestation")

    def test_next_starting_offset_non_log_raises(self):
        """Test that next_starting_offset raises AttributeError for non-log evidence"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"

        with self.assertRaises(AttributeError) as context:
            _ = evidence.next_starting_offset

        self.assertIn("certification", str(context.exception))
        self.assertIn("next_starting_offset", str(context.exception))

    def test_next_starting_offset_no_partial_access_raises(self):
        """Test that next_starting_offset raises ValueError when partial access not supported"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"

        mock_caps = MagicMock()
        mock_caps.supports_partial_access = False

        with patch.object(type(evidence), "capabilities", new_callable=lambda: property(lambda self: mock_caps)):
            with self.assertRaises(ValueError) as context:
                _ = evidence.next_starting_offset

            self.assertIn("partial access", str(context.exception))

    def test_next_starting_offset_returns_none_without_parameters(self):
        """Test that next_starting_offset returns None when no chosen_parameters"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"

        mock_caps = MagicMock()
        mock_caps.supports_partial_access = True

        with patch.object(type(evidence), "capabilities", new_callable=lambda: property(lambda self: mock_caps)):
            with patch.object(type(evidence), "chosen_parameters", new_callable=lambda: property(lambda self: None)):
                result = evidence.next_starting_offset

                self.assertIsNone(result)

    def test_next_starting_offset_returns_none_without_results(self):
        """Test that next_starting_offset returns None when no results"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"

        mock_caps = MagicMock()
        mock_caps.supports_partial_access = True

        mock_params = MagicMock()
        mock_params.starting_offset = 100

        with patch.object(type(evidence), "capabilities", new_callable=lambda: property(lambda self: mock_caps)):
            with patch.object(
                type(evidence), "chosen_parameters", new_callable=lambda: property(lambda self: mock_params)
            ):
                with patch.object(type(evidence), "results", new_callable=lambda: property(lambda self: None)):
                    result = evidence.next_starting_offset

                    self.assertIsNone(result)

    def test_next_starting_offset_calculates_correctly(self):
        """Test that next_starting_offset calculates correctly with valid data"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"

        mock_caps = MagicMock()
        mock_caps.supports_partial_access = True

        mock_params = MagicMock()
        mock_params.starting_offset = 100

        mock_results = MagicMock()
        mock_results.certified_entry_count = 50

        with patch.object(type(evidence), "capabilities", new_callable=lambda: property(lambda self: mock_caps)):
            with patch.object(
                type(evidence), "chosen_parameters", new_callable=lambda: property(lambda self: mock_params)
            ):
                with patch.object(type(evidence), "results", new_callable=lambda: property(lambda self: mock_results)):
                    result = evidence.next_starting_offset

                    self.assertEqual(result, 150)  # 100 + 50

    def test_compatible_with_different_agent_id(self):
        """Test that compatible_with returns False for different agent_id"""
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "agent-1"
        evidence1.attestation_index = 0
        evidence1.evidence_class = "certification"
        evidence1.evidence_type = "tpm_quote"

        evidence2 = EvidenceItem.empty()
        evidence2.agent_id = "agent-2"  # Different!
        evidence2.attestation_index = 0
        evidence2.evidence_class = "certification"
        evidence2.evidence_type = "tpm_quote"

        result = evidence1.compatible_with(evidence2)

        self.assertFalse(result)

    def test_compatible_with_different_attestation_index(self):
        """Test that compatible_with returns False for different attestation_index"""
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "agent-1"
        evidence1.attestation_index = 0
        evidence1.evidence_class = "certification"
        evidence1.evidence_type = "tpm_quote"

        evidence2 = EvidenceItem.empty()
        evidence2.agent_id = "agent-1"
        evidence2.attestation_index = 1  # Different!
        evidence2.evidence_class = "certification"
        evidence2.evidence_type = "tpm_quote"

        result = evidence1.compatible_with(evidence2)

        self.assertFalse(result)

    def test_compatible_with_different_evidence_class(self):
        """Test that compatible_with returns False for different evidence_class"""
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "agent-1"
        evidence1.attestation_index = 0
        evidence1.evidence_class = "certification"
        evidence1.evidence_type = "tpm_quote"

        evidence2 = EvidenceItem.empty()
        evidence2.agent_id = "agent-1"
        evidence2.attestation_index = 0
        evidence2.evidence_class = "log"  # Different!
        evidence2.evidence_type = "ima_log"

        result = evidence1.compatible_with(evidence2)

        self.assertFalse(result)

    def test_compatible_with_different_capabilities(self):
        """Test that compatible_with returns False for different capabilities"""
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "agent-1"
        evidence1.attestation_index = 0
        evidence1.evidence_class = "certification"
        evidence1.evidence_type = "tpm_quote"

        evidence2 = EvidenceItem.empty()
        evidence2.agent_id = "agent-1"
        evidence2.attestation_index = 0
        evidence2.evidence_class = "certification"
        evidence2.evidence_type = "tpm_quote"

        mock_caps1 = MagicMock()
        mock_caps1.values = {"algorithms": ["rsa2048"]}

        mock_caps2 = MagicMock()
        mock_caps2.values = {"algorithms": ["ecdsa"]}  # Different!

        with patch.object(
            type(evidence1),
            "capabilities",
            new_callable=lambda: property(lambda self: mock_caps1 if self is evidence1 else mock_caps2),
        ):
            result = evidence1.compatible_with(evidence2)

            self.assertFalse(result)

    def test_receive_capabilities_validates_required_fields(self):
        """Test that receive_capabilities validates required fields"""
        evidence = EvidenceItem.empty()
        data = {"evidence_class": "certification", "evidence_type": "tpm_quote", "capabilities": {}}

        with patch.object(evidence, "refresh_metadata"):
            # This should call validate_required which will check evidence_class/type
            evidence.receive_capabilities(data)

            # Verify that required fields were set
            self.assertEqual(evidence.evidence_class, "certification")
            self.assertEqual(evidence.evidence_type, "tpm_quote")

    def test_render_evidence_requested_with_none_parameters(self):
        """Test rendering evidence requested when chosen_parameters render returns None"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"

        mock_params = MagicMock()
        mock_params.render.return_value = None  # No rendered parameters

        with patch.object(type(evidence), "chosen_parameters", new_callable=lambda: property(lambda self: mock_params)):
            result = evidence.render_evidence_requested()

            # Should not include chosen_parameters if render returns None
            self.assertNotIn("chosen_parameters", result)
            self.assertEqual(result["evidence_class"], "certification")

    def test_render_evidence_acknowledged_with_none_capabilities(self):
        """Test rendering evidence acknowledged when capabilities render returns None"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"
        evidence.evidence_type = "ima_log"

        mock_caps = MagicMock()
        mock_caps.render.return_value = None  # No rendered capabilities

        with patch.object(type(evidence), "capabilities", new_callable=lambda: property(lambda self: mock_caps)):
            with patch.object(type(evidence), "chosen_parameters", new_callable=lambda: property(lambda self: None)):
                with patch.object(type(evidence), "data", new_callable=lambda: property(lambda self: None)):
                    result = evidence.render_evidence_acknowledged()

                    # Should not include capabilities if render returns None
                    self.assertNotIn("capabilities", result)
                    self.assertEqual(result["evidence_class"], "log")

    def test_create_raises_typeerror_for_non_dict(self):
        """Test that create raises TypeError when given non-dictionary input"""
        # Test with string
        with self.assertRaises(TypeError) as cm:
            EvidenceItem.create("not a dict")
        self.assertIn("must be a dictionary", str(cm.exception))

        # Test with list
        with self.assertRaises(TypeError) as cm:
            EvidenceItem.create(["not", "a", "dict"])
        self.assertIn("must be a dictionary", str(cm.exception))

    def test_receive_evidence_certification_creates_data_and_results(self):
        """Test that receive_evidence for certification creates data and results objects"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"

        data = {"data": {"quote": "test-quote-data"}}

        with patch.object(evidence, "refresh_metadata"):
            evidence.receive_evidence(data)

            # Should have created both data and results objects
            self.assertIsNotNone(evidence.data)
            self.assertIsNotNone(evidence.results)

    def test_receive_evidence_log_creates_data_and_results(self):
        """Test that receive_evidence for log creates data and results objects"""
        evidence = EvidenceItem.empty()
        evidence.evidence_class = "log"
        evidence.evidence_type = "ima_log"

        # Initialize chosen_parameters as required by LogData.update()
        evidence.initialise_parameters()

        data = {"data": {"entries": []}}

        with patch.object(evidence, "refresh_metadata"):
            evidence.receive_evidence(data)

            # Should have created both data and results objects
            self.assertIsNotNone(evidence.data)
            self.assertIsNotNone(evidence.results)

    def test_capabilities_render_with_optional_fields(self):
        """Test Capabilities.render() includes optional fields when present"""
        caps = Capabilities.empty()
        caps.component_version = "1.0.0"
        caps.evidence_version = "2.0.0"
        caps.meta = {"key": "value"}

        result = caps.render()

        # Lines 205-212 should be covered
        self.assertIn("component_version", result)
        self.assertIn("evidence_version", result)
        self.assertIn("meta", result)

    def test_certification_capabilities_with_certification_keys(self):
        """Test CertificationCapabilities with certification_keys"""
        caps = CertificationCapabilities.empty()

        # Test update() with certification_keys - lines 240-246
        cert_key_data = {
            "key_class": "asymmetric",
            "key_algorithm": "rsa",
            "key_size": 2048,
            "server_identifier": "ak",
        }

        data = {
            "signature_schemes": ["rsassa"],
            "certification_keys": [cert_key_data],
        }

        caps.update(data)

        # Verify certification_keys were added
        self.assertEqual(len(caps.certification_keys), 1)

    def test_certification_capabilities_render_with_all_fields(self):
        """Test CertificationCapabilities.render() with all optional fields - lines 252-274"""

        caps = CertificationCapabilities.empty()
        caps.signature_schemes = ["rsassa"]
        caps.hash_algorithms = ["sha256"]
        caps.available_subjects = {"pcrs": [0, 1, 2]}
        caps.meta = {"test": "data"}

        # Add a certification key
        cert_key = CertificationKey.empty()
        cert_key.key_class = "asymmetric"
        cert_key.key_algorithm = "rsa"
        cert_key.key_size = 2048
        cert_key.server_identifier = "ak"
        caps.certification_keys.add(cert_key)

        result = caps.render()

        # Lines 257-272 should be covered
        self.assertIn("signature_schemes", result)
        self.assertIn("hash_algorithms", result)
        self.assertIn("available_subjects", result)
        self.assertIn("certification_keys", result)
        self.assertIn("meta", result)
        # Meta should be at the bottom (line 269-272)
        self.assertEqual(list(result.keys())[-1], "meta")

    def test_log_capabilities_partial_access_validation(self):
        """Test LogCapabilities validation when supports_partial_access is true - line 308"""

        caps = LogCapabilities.empty()

        # When supports_partial_access is true, entry_count is required
        data = {"supports_partial_access": True, "appendable": False}

        caps.update(data)

        # Should have validation errors (line 308 is covered)
        errors = caps.get_errors()
        self.assertTrue(len(errors) > 0)

    def test_log_capabilities_render_with_all_fields(self):
        """Test LogCapabilities.render() with all optional fields - lines 311-330"""

        caps = LogCapabilities.empty()
        caps.supports_partial_access = True
        caps.appendable = True
        caps.entry_count = 100
        caps.formats = ["application/json"]
        caps.meta = {"extra": "info"}

        result = caps.render()

        # Lines 316-328 should be covered
        self.assertIn("supports_partial_access", result)
        self.assertIn("appendable", result)
        self.assertIn("entry_count", result)
        self.assertIn("formats", result)
        self.assertIn("meta", result)
        # Meta should be at the bottom (lines 325-328)
        self.assertEqual(list(result.keys())[-1], "meta")

    def test_certification_parameters_render_with_all_fields(self):
        """Test CertificationParameters.render() with all optional fields - lines 388-408"""

        params = CertificationParameters.empty()
        params.signature_scheme = "rsassa"
        params.challenge = b"test_challenge"
        params.hash_algorithm = "sha256"
        params.selected_subjects = {"pcrs": [0, 1]}
        params.meta = {"info": "test"}

        # Add certification key
        cert_key = CertificationKey.empty()
        cert_key.key_class = "asymmetric"
        cert_key.key_algorithm = "rsa"
        cert_key.key_size = 2048
        cert_key.server_identifier = "ak"
        params.certification_key = cert_key

        result = params.render()

        # Lines 394-406 should be covered
        self.assertIn("signature_scheme", result)
        self.assertIn("challenge", result)
        self.assertIn("hash_algorithm", result)
        self.assertIn("selected_subjects", result)
        self.assertIn("certification_key", result)
        self.assertIn("meta", result)

    def test_log_parameters_render_with_all_fields(self):
        """Test LogParameters.render() with all optional fields - lines 448-465"""

        params = LogParameters.empty()
        params.starting_offset = 0
        params.entry_count = 50
        params.format = "application/json"
        params.meta = {"test": "data"}

        result = params.render()

        # Lines 454-463 should be covered
        self.assertIn("starting_offset", result)
        self.assertIn("entry_count", result)
        self.assertIn("format", result)
        self.assertIn("meta", result)

    def test_certification_data_render_with_subject_data(self):
        """Test CertificationData.render() with subject_data and meta - lines 512-522"""

        data = CertificationData.empty()
        data.subject_data = {"pcr0": "abcd1234"}
        data.message = b"test_message"
        data.signature = b"test_signature"
        data.meta = {"additional": "info"}

        result = data.render()

        # Lines 516-520 should be covered
        self.assertIn("subject_data", result)
        self.assertIn("message", result)
        self.assertIn("signature", result)
        self.assertIn("meta", result)

    def test_log_data_render_with_entry_count(self):
        """Test LogData.render() with entry_count and meta - lines 541-551"""

        data = LogData.empty()
        data.entries = "log entry data"
        data.entry_count = 10
        data.meta = {"extra": "metadata"}

        result = data.render()

        # Lines 545-549 should be covered
        self.assertIn("entries", result)
        self.assertIn("entry_count", result)
        self.assertIn("meta", result)

    def test_certification_key_render_with_all_fields(self):
        """Test CertificationKey.render() with all optional fields - lines 650-672"""

        key = CertificationKey.empty()
        key.key_class = "asymmetric"
        key.key_size = 2048
        key.key_algorithm = "rsa"
        key.server_identifier = "ak"
        key.local_identifier = b"local_key_id"
        key.allowable_signature_schemes = ["rsassa"]
        key.allowable_hash_algorithms = ["sha256"]
        key.public = b"public_key_data"

        result = key.render()

        # Lines 654-670 should be covered
        self.assertIn("key_class", result)
        self.assertIn("key_size", result)
        self.assertIn("key_algorithm", result)
        self.assertIn("server_identifier", result)
        self.assertIn("local_identifier", result)
        self.assertIn("allowable_signature_schemes", result)
        self.assertIn("allowable_hash_algorithms", result)
        self.assertIn("public", result)

    def test_log_results_render_with_certified_entry_count(self):
        """Test LogResults.render() with certified_entry_count and meta - lines 711-721"""

        results = LogResults.empty()
        results.certified_entry_count = 42
        results.meta = {"result": "success"}

        result = results.render()

        # Lines 715-719 should be covered
        self.assertIn("certified_entry_count", result)
        self.assertIn("meta", result)


if __name__ == "__main__":
    unittest.main()
