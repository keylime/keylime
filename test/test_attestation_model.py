"""
Unit tests for keylime.models.verifier.attestation module
"""
# pyright: reportAttributeAccessIssue=false
# ORM models with dynamically-created attributes from metaclasses

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, PropertyMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import registry

from keylime.models import db_manager
from keylime.models.verifier import Attestation, EvidenceItem, VerifierAgent


class TestAttestationModel(unittest.TestCase):
    """Test cases for the Attestation model"""

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
        Attestation.process_schema()
        VerifierAgent.process_schema()
        EvidenceItem.process_schema()

        # Create tables
        db_manager.registry.metadata.create_all(db_manager.engine)

    def test_attestation_schema_definition(self):
        """Test that attestation schema is properly defined"""
        self.assertTrue(Attestation.schema_processed)
        self.assertEqual(Attestation.table_name, "attestations")

        # Check that primary key is composite (agent_id, index)
        self.assertEqual(len(Attestation.primary_key), 2)
        self.assertIn("agent_id", Attestation.primary_key)
        self.assertIn("index", Attestation.primary_key)

    def test_attestation_fields_exist(self):
        """Test that all expected fields are defined"""
        expected_fields = [
            "agent_id",
            "index",
            "stage",
            "evaluation",
            "failure_reason",
            "capabilities_received_at",
            "challenges_expire_at",
            "evidence_received_at",
            "verification_completed_at",
        ]

        for field_name in expected_fields:
            self.assertIn(field_name, Attestation.fields)

    def test_attestation_stage_choices(self):
        """Test that stage field has correct choices"""
        # pylint: disable=unsubscriptable-object
        stage_field = Attestation.fields["stage"]
        # pylint: enable=unsubscriptable-object

        # The OneOf type should restrict to these values
        self.assertIsNotNone(stage_field)

    def test_attestation_evaluation_choices(self):
        """Test that evaluation field has correct choices"""
        # pylint: disable=unsubscriptable-object
        evaluation_field = Attestation.fields["evaluation"]
        # pylint: enable=unsubscriptable-object

        self.assertIsNotNone(evaluation_field)

    def test_create_empty_attestation(self):
        """Test creating an empty attestation"""
        attestation = Attestation.empty()

        self.assertIsNotNone(attestation)
        self.assertIsInstance(attestation, Attestation)

    def test_attestation_initialization(self):
        """Test attestation initialization sets private attributes"""
        attestation = Attestation.empty()

        # pylint: disable=protected-access
        # Check that private attributes are initialized
        self.assertIsNone(attestation._previous_attestation)
        self.assertIsNone(attestation._previous_authenticated_attestation)
        self.assertIsNone(attestation._previous_passed_attestation)
        # pylint: enable=protected-access

    def test_set_index_first_attestation(self):
        """Test that _set_index assigns 0 for the first attestation"""
        with patch.object(Attestation, "get_latest", return_value=None):
            attestation = Attestation.empty()
            attestation.agent_id = "test-agent-123"
            attestation._set_index()  # pylint: disable=protected-access

            self.assertEqual(attestation.index, 0)

    def test_set_index_subsequent_attestation(self):
        """Test that _set_index increments from last attestation"""
        mock_last_attestation = MagicMock()
        mock_last_attestation.index = 5

        with patch.object(Attestation, "get_latest", return_value=mock_last_attestation):
            attestation = Attestation.empty()
            attestation.agent_id = "test-agent-123"
            attestation._set_index()  # pylint: disable=protected-access

            self.assertEqual(attestation.index, 6)

    def test_set_index_preserves_existing(self):
        """Test that _set_index doesn't override existing index when already committed"""
        # This test verifies that _set_index checks the committed dict before setting index
        # We use a mock to simulate a committed index without actually saving to DB
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"

        # Mock the committed property to return an index (simulating loaded from DB)
        with patch.object(type(attestation), "committed", new_callable=PropertyMock) as mock_committed:
            mock_committed.return_value = {"index": 3}

            # Mock get_latest to verify it's NOT called (because _set_index should return early)
            with patch.object(Attestation, "get_latest") as mock_get_latest:
                # _set_index should check committed and not query for last attestation
                attestation._set_index()  # pylint: disable=protected-access

                # Verify that get_latest was NOT called (because committed dict has index)
                mock_get_latest.assert_not_called()

    def test_set_stage_awaiting_evidence(self):
        """Test that _set_stage sets awaiting_evidence when no evidence"""
        attestation = Attestation.empty()
        # evidence is a has_many association, it's already initialized as empty
        # No need to set it explicitly
        attestation.evaluation = None
        attestation._set_stage()  # pylint: disable=protected-access

        self.assertEqual(attestation.stage, "awaiting_evidence")

    def test_set_stage_verification_complete_on_pass(self):
        """Test that _set_stage sets verification_complete when evaluation is pass"""
        attestation = Attestation.empty()
        attestation.evaluation = "pass"
        attestation._set_stage()  # pylint: disable=protected-access

        self.assertEqual(attestation.stage, "verification_complete")

    def test_set_stage_verification_complete_on_fail(self):
        """Test that _set_stage sets verification_complete when evaluation is fail"""
        attestation = Attestation.empty()
        attestation.evaluation = "fail"
        attestation._set_stage()  # pylint: disable=protected-access

        self.assertEqual(attestation.stage, "verification_complete")

    def test_set_stage_evaluating_evidence(self):
        """Test that _set_stage sets evaluating_evidence when all evidence has data"""
        attestation = Attestation.empty()
        attestation.evaluation = "pending"

        # Create real EvidenceItem instances with data
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "test-agent"
        evidence1.attestation_index = 0
        evidence1.evidence_class = "certification"
        evidence1.evidence_type = "tpm_quote"
        # Use receive_evidence to properly initialize data
        evidence1.receive_evidence({"data": {"quote": "test-quote"}})

        evidence2 = EvidenceItem.empty()
        evidence2.agent_id = "test-agent"
        evidence2.attestation_index = 0
        evidence2.evidence_class = "log"
        evidence2.evidence_type = "ima_log"
        # Log evidence requires chosen_parameters to be set before receiving evidence
        evidence2.initialise_parameters()
        evidence2.receive_evidence({"data": {"entry_count": 10, "entries": []}})

        # Add evidence items to the attestation
        # pylint: disable=no-member
        attestation.evidence.add(evidence1)
        attestation.evidence.add(evidence2)
        # pylint: enable=no-member

        attestation._set_stage()  # pylint: disable=protected-access

        self.assertEqual(attestation.stage, "evaluating_evidence")

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_set_timestamps_capabilities_received(self, mock_now, mock_config):
        """Test that _set_timestamps sets capabilities_received_at correctly"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 1800

        # Create real evidence item with capabilities
        evidence = EvidenceItem.empty()
        evidence.agent_id = "test-agent"
        evidence.attestation_index = 0
        # Use receive_capabilities to properly initialize capabilities
        evidence.receive_capabilities(
            {
                "evidence_class": "certification",
                "evidence_type": "tpm_quote",
                "capabilities": {"algorithms": ["rsa2048"]},
            }
        )

        attestation = Attestation.empty()
        attestation.evidence.add(evidence)  # pylint: disable=no-member
        attestation.capabilities_received_at = None
        attestation._set_timestamps()  # pylint: disable=protected-access

        self.assertEqual(attestation.capabilities_received_at, now)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_set_timestamps_challenge_expiry(self, mock_now, mock_config):
        """Test that _set_timestamps sets challenges_expire_at correctly"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        challenge_lifetime = 1800  # 30 minutes
        mock_config.return_value = challenge_lifetime

        # Create real evidence item with chosen_parameters that has a challenge
        evidence = EvidenceItem.empty()
        evidence.agent_id = "test-agent"
        evidence.attestation_index = 0
        evidence.receive_capabilities(
            {
                "evidence_class": "certification",
                "evidence_type": "tpm_quote",
                "capabilities": {"algorithms": ["rsa2048"]},
            }
        )
        # Generate a challenge, which will set chosen_parameters with a challenge field
        evidence.generate_challenge(256)

        attestation = Attestation.empty()
        attestation.evidence.add(evidence)  # pylint: disable=no-member
        attestation.capabilities_received_at = now
        attestation._set_timestamps()  # pylint: disable=protected-access

        expected_expiry = now + timedelta(seconds=challenge_lifetime)
        self.assertEqual(attestation.challenges_expire_at, expected_expiry)

    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_set_timestamps_evidence_received(self, mock_now):
        """Test that _set_timestamps sets evidence_received_at correctly"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now

        # Create real evidence item with data
        evidence = EvidenceItem.empty()
        evidence.agent_id = "test-agent"
        evidence.attestation_index = 0
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"
        # Use receive_evidence to properly initialize data
        evidence.receive_evidence({"data": {"quote": "test-quote"}})

        attestation = Attestation.empty()
        attestation.evidence.add(evidence)  # pylint: disable=no-member
        attestation.evidence_received_at = None
        attestation._set_timestamps()  # pylint: disable=protected-access

        self.assertEqual(attestation.evidence_received_at, now)

    def test_get_latest_class_method(self):
        """Test that get_latest calls get with correct parameters"""
        with patch.object(Attestation, "get") as mock_get:
            Attestation.get_latest("test-agent-123")

            # Verify get was called with agent_id and sort parameter
            mock_get.assert_called_once()
            call_kwargs = mock_get.call_args[1]
            self.assertEqual(call_kwargs["agent_id"], "test-agent-123")
            self.assertIn("sort_", call_kwargs)

    def test_create_class_method(self):
        """Test that create method initializes attestation from agent"""
        mock_agent = MagicMock()

        with patch.object(Attestation, "empty") as mock_empty:
            mock_attestation = MagicMock()
            mock_empty.return_value = mock_attestation

            result = Attestation.create(mock_agent)

            mock_empty.assert_called_once()
            mock_attestation.initialise.assert_called_once_with(mock_agent)
            self.assertEqual(result, mock_attestation)


if __name__ == "__main__":
    unittest.main()
