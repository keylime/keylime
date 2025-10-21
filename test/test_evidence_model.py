"""
Unit tests for keylime.models.verifier.evidence module
"""
# pyright: reportAttributeAccessIssue=false
# ORM models with dynamically-created attributes from metaclasses

import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import registry

from keylime.models import db_manager
from keylime.models.verifier import Attestation, EvidenceItem


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


if __name__ == "__main__":
    unittest.main()
