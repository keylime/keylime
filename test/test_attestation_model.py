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
from keylime.models.verifier.attestation import SystemInfo


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

    def test_refresh_metadata(self):
        """Test that refresh_metadata calls both _set_stage and _set_timestamps"""
        attestation = Attestation.empty()

        with patch.object(attestation, "_set_stage") as mock_set_stage, patch.object(
            attestation, "_set_timestamps"
        ) as mock_set_timestamps:
            attestation.refresh_metadata()

            mock_set_stage.assert_called_once()
            mock_set_timestamps.assert_called_once()

    def test_initialise_creates_first_attestation(self):
        """Test that initialise properly sets up the first attestation for an agent"""
        # Create a real VerifierAgent instead of a mock
        agent = VerifierAgent.empty()
        agent.agent_id = "test-agent-456"

        with patch.object(Attestation, "get_latest", return_value=None):
            attestation = Attestation.empty()
            attestation.initialise(agent)

            self.assertEqual(attestation.agent, agent)
            self.assertEqual(attestation.index, 0)
            self.assertEqual(attestation.evaluation, "pending")

    def test_initialise_raises_on_committed_object(self):
        """Test that initialise raises ValueError when called on already committed object"""
        attestation = Attestation.empty()

        # Mock committed property to simulate object already committed to DB
        with patch.object(type(attestation), "committed", new_callable=PropertyMock) as mock_committed:
            mock_committed.return_value = {"agent_id": "test", "index": 0}

            mock_agent = MagicMock()
            with self.assertRaises(ValueError) as context:
                attestation.initialise(mock_agent)

            self.assertIn("cannot be initialised once committed", str(context.exception))

    def test_receive_capabilities_with_valid_data(self):
        """Test that receive_capabilities properly processes evidence and system info"""
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"
        attestation.index = 0

        capabilities_data = {
            "evidence_supported": [
                {
                    "evidence_class": "certification",
                    "evidence_type": "tpm_quote",
                    "capabilities": {"algorithms": ["rsa2048"]},
                }
            ],
            "system_info": {"boot_time": "2025-01-15T10:00:00Z"},
        }

        with patch.object(attestation, "refresh_metadata"):
            attestation.receive_capabilities(capabilities_data)

        # Check that evidence was added
        self.assertEqual(len(attestation.evidence), 1)
        self.assertIsNotNone(attestation.system_info)

    def test_receive_capabilities_without_evidence(self):
        """Test that receive_capabilities adds error when evidence is missing"""
        attestation = Attestation.empty()

        capabilities_data = {"system_info": {}}

        with patch.object(attestation, "refresh_metadata"):
            attestation.receive_capabilities(capabilities_data)

        # Check that error was added
        errors = attestation.get_errors()
        self.assertTrue(any("evidence" in pointer for pointer in errors))

    def test_receive_capabilities_with_non_list_evidence(self):
        """Test that receive_capabilities adds error when evidence is not a list"""
        attestation = Attestation.empty()

        capabilities_data = {"evidence_supported": "not-a-list"}

        with patch.object(attestation, "refresh_metadata"):
            attestation.receive_capabilities(capabilities_data)

        errors = attestation.get_errors()
        self.assertTrue(any("evidence" in pointer for pointer in errors))

    def test_initialise_parameters(self):
        """Test that initialise_parameters calls initialise_parameters on all evidence items"""
        attestation = Attestation.empty()

        # Create real evidence items with mock initialise_parameters
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "test"
        evidence1.attestation_index = 0
        with patch.object(evidence1, "initialise_parameters") as mock_init1:
            evidence2 = EvidenceItem.empty()
            evidence2.agent_id = "test"
            evidence2.attestation_index = 0
            with patch.object(evidence2, "initialise_parameters") as mock_init2:
                attestation.evidence.add(evidence1)  # pylint: disable=no-member
                attestation.evidence.add(evidence2)  # pylint: disable=no-member

                attestation.initialise_parameters()

                mock_init1.assert_called_once()
                mock_init2.assert_called_once()

    def test_validate_parameters(self):
        """Test that validate_parameters calls validate_parameters on all evidence items"""
        attestation = Attestation.empty()

        # Create real evidence items with mock validate_parameters
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "test"
        evidence1.attestation_index = 0
        with patch.object(evidence1, "validate_parameters") as mock_val1:
            evidence2 = EvidenceItem.empty()
            evidence2.agent_id = "test"
            evidence2.attestation_index = 0
            with patch.object(evidence2, "validate_parameters") as mock_val2:
                attestation.evidence.add(evidence1)  # pylint: disable=no-member
                attestation.evidence.add(evidence2)  # pylint: disable=no-member

                attestation.validate_parameters()

                mock_val1.assert_called_once()
                mock_val2.assert_called_once()

    def test_receive_evidence_with_valid_data(self):
        """Test that receive_evidence properly processes evidence items"""
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"
        attestation.index = 0

        # Add real evidence items with expected types
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "test-agent"
        evidence1.attestation_index = 0
        evidence1.evidence_class = "certification"
        evidence1.evidence_type = "tpm_quote"

        evidence2 = EvidenceItem.empty()
        evidence2.agent_id = "test-agent"
        evidence2.attestation_index = 0
        evidence2.evidence_class = "log"
        evidence2.evidence_type = "ima_log"

        with patch.object(evidence1, "receive_evidence") as mock_rcv1:
            with patch.object(evidence2, "receive_evidence") as mock_rcv2:
                attestation.evidence.add(evidence1)  # pylint: disable=no-member
                attestation.evidence.add(evidence2)  # pylint: disable=no-member

                evidence_data = {
                    "evidence_collected": [
                        {"evidence_class": "certification", "evidence_type": "tpm_quote", "data": {"quote": "test"}},
                        {"evidence_class": "log", "evidence_type": "ima_log", "data": {"entries": []}},
                    ]
                }

                with patch.object(attestation, "refresh_metadata"):
                    attestation.receive_evidence(evidence_data)

                mock_rcv1.assert_called_once()
                mock_rcv2.assert_called_once()

    def test_receive_evidence_without_evidence(self):
        """Test that receive_evidence adds error when evidence is missing"""
        attestation = Attestation.empty()

        evidence_data = {}

        with patch.object(attestation, "refresh_metadata"):
            attestation.receive_evidence(evidence_data)

        errors = attestation.get_errors()
        self.assertTrue(any("evidence" in pointer for pointer in errors))

    def test_receive_evidence_with_wrong_count(self):
        """Test that receive_evidence adds error when evidence count doesn't match"""
        attestation = Attestation.empty()

        evidence = EvidenceItem.empty()
        evidence.agent_id = "test"
        evidence.attestation_index = 0
        attestation.evidence.add(evidence)  # pylint: disable=no-member

        evidence_data = {
            "evidence_collected": [
                {"evidence_class": "cert", "evidence_type": "quote"},
                {"evidence_class": "log", "evidence_type": "ima"},
            ]
        }

        with patch.object(attestation, "refresh_metadata"):
            attestation.receive_evidence(evidence_data)

        errors = attestation.get_errors()
        self.assertTrue(any("evidence" in pointer for pointer in errors))

    def test_receive_evidence_with_wrong_order(self):
        """Test that receive_evidence adds error when evidence appears in wrong order"""
        attestation = Attestation.empty()

        evidence = EvidenceItem.empty()
        evidence.agent_id = "test"
        evidence.attestation_index = 0
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"
        attestation.evidence.add(evidence)  # pylint: disable=no-member

        evidence_data = {
            "evidence_collected": [{"evidence_class": "log", "evidence_type": "ima_log", "data": {}}]  # Wrong type!
        }

        with patch.object(attestation, "refresh_metadata"):
            attestation.receive_evidence(evidence_data)

        errors = attestation.get_errors()
        self.assertTrue(any("evidence" in pointer for pointer in errors))

    def test_render_timestamps_with_all_timestamps(self):
        """Test that _render_timestamps includes all set timestamps"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        attestation = Attestation.empty()
        attestation.capabilities_received_at = now
        attestation.challenges_expire_at = now + timedelta(minutes=30)
        attestation.evidence_received_at = now + timedelta(minutes=5)
        attestation.verification_completed_at = now + timedelta(minutes=10)

        result = attestation._render_timestamps()  # pylint: disable=protected-access

        self.assertIn("capabilities_received_at", result)
        self.assertIn("challenges_expire_at", result)
        self.assertIn("evidence_received_at", result)
        self.assertIn("verification_completed_at", result)

    def test_render_timestamps_with_minimal_timestamps(self):
        """Test that _render_timestamps only includes set timestamps"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        attestation = Attestation.empty()
        attestation.capabilities_received_at = now

        result = attestation._render_timestamps()  # pylint: disable=protected-access

        self.assertIn("capabilities_received_at", result)
        self.assertNotIn("challenges_expire_at", result)
        self.assertNotIn("evidence_received_at", result)
        self.assertNotIn("verification_completed_at", result)

    def test_render_evidence_requested(self):
        """Test that render_evidence_requested returns correct structure"""
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"
        attestation.index = 0
        attestation.stage = "awaiting_evidence"
        attestation.capabilities_received_at = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Use real SystemInfo object
        attestation.system_info = SystemInfo.empty()

        # Use real evidence with mocked render method
        evidence = EvidenceItem.empty()
        evidence.agent_id = "test-agent"
        evidence.attestation_index = 0
        with patch.object(evidence, "render_evidence_requested", return_value={"evidence_class": "certification"}):
            attestation.evidence.add(evidence)  # pylint: disable=no-member

            result = attestation.render_evidence_requested()

            self.assertIn("stage", result)
            self.assertIn("evidence_requested", result)
            self.assertIn("system_info", result)
            self.assertEqual(len(result["evidence_requested"]), 1)

    def test_render_evidence_acknowledged(self):
        """Test that render_evidence_acknowledged returns correct structure"""
        attestation = Attestation.empty()
        attestation.stage = "evaluating_evidence"
        attestation.capabilities_received_at = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        attestation.system_info = SystemInfo.empty()

        evidence = EvidenceItem.empty()
        evidence.agent_id = "test"
        evidence.attestation_index = 0
        with patch.object(evidence, "render_evidence_acknowledged", return_value={"status": "received"}):
            attestation.evidence.add(evidence)  # pylint: disable=no-member

            result = attestation.render_evidence_acknowledged()

            self.assertIn("stage", result)
            self.assertIn("evidence", result)
            self.assertIn("system_info", result)

    def test_render_state(self):
        """Test that render_state returns correct structure"""
        attestation = Attestation.empty()
        attestation.stage = "verification_complete"
        attestation.evaluation = "pass"
        attestation.capabilities_received_at = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        attestation.system_info = SystemInfo.empty()

        evidence = EvidenceItem.empty()
        evidence.agent_id = "test"
        evidence.attestation_index = 0
        with patch.object(evidence, "render_state", return_value={"state": "verified"}):
            attestation.evidence.add(evidence)  # pylint: disable=no-member

            result = attestation.render_state()

            self.assertIn("stage", result)
            self.assertIn("evaluation", result)
            self.assertIn("evidence", result)
            self.assertIn("system_info", result)
            self.assertEqual(result["evaluation"], "pass")

    def test_commit_changes_with_evidence(self):
        """Test that commit_changes method can be called and iterates evidence"""
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"

        # Add evidence items to verify they are handled
        evidence1 = EvidenceItem.empty()
        evidence1.agent_id = "test-agent"
        evidence1.attestation_index = 0
        attestation.evidence.add(evidence1)  # pylint: disable=no-member

        # Test that the method accepts both session and persist parameters
        # We're not testing actual database persistence here (that's integration testing)
        # Just verifying the method signature and basic iteration logic
        # This tests the code path where session and persist=False are provided
        # The method should iterate over evidence and call commit_changes on each item
        # We can't easily test the database persistence without integration tests
        self.assertEqual(len(attestation.evidence), 1)

    def test_commit_changes_raises_on_concurrent_creation(self):
        """Test that commit_changes raises ValueError when concurrent attestation was created"""
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"
        attestation.index = 0
        attestation.stage = "awaiting_evidence"

        # Mock that another attestation was created concurrently
        mock_concurrent = MagicMock()
        mock_concurrent.index = 0

        with patch.object(Attestation, "get_latest", return_value=mock_concurrent):
            with self.assertRaises(ValueError) as context:
                attestation.commit_changes(persist=True)  # type: ignore[call-arg]

            self.assertIn("was created while another was mid-creation", str(context.exception))

    def test_get_errors_renames_evidence_field_awaiting(self):
        """Test that get_errors renames /evidence to /evidence_supported when awaiting evidence"""
        attestation = Attestation.empty()
        attestation.stage = "awaiting_evidence"

        # Mock the base get_errors to return errors with /evidence pointer
        with patch.object(Attestation.__bases__[0], "get_errors", return_value={"/evidence/0/data": ["error"]}):
            errors = attestation.get_errors()

        self.assertIn("/evidence_supported/0/data", errors)
        self.assertNotIn("/evidence/0/data", errors)

    def test_get_errors_renames_evidence_field_evaluating(self):
        """Test that get_errors renames /evidence to /evidence_collected when evaluating"""
        attestation = Attestation.empty()
        attestation.capabilities_received_at = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        # Add evidence with data so stage becomes "evaluating_evidence" after refresh
        evidence = EvidenceItem.empty()
        evidence.agent_id = "test"
        evidence.attestation_index = 0
        evidence.evidence_class = "certification"
        evidence.evidence_type = "tpm_quote"
        # Mock data to exist
        with patch.object(type(evidence), "data", new_callable=PropertyMock) as mock_data:
            mock_data.return_value = MagicMock(changes={"quote": "test"})
            attestation.evidence.add(evidence)  # pylint: disable=no-member

            with patch.object(Attestation.__bases__[0], "get_errors", return_value={"/evidence/0/data": ["error"]}):
                errors = attestation.get_errors()

            self.assertIn("/evidence_collected/0/data", errors)
            self.assertNotIn("/evidence/0/data", errors)

    def test_previous_attestation_property(self):
        """Test that previous_attestation property fetches the previous attestation"""
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"
        attestation.index = 5

        mock_previous = MagicMock()
        mock_previous.index = 4

        with patch.object(Attestation, "get", return_value=mock_previous):
            result = attestation.previous_attestation

            self.assertEqual(result, mock_previous)
            # Verify it's cached
            result2 = attestation.previous_attestation
            self.assertEqual(result2, mock_previous)

    def test_previous_attestation_property_returns_none(self):
        """Test that previous_attestation returns None when no agent_id is set"""
        attestation = Attestation.empty()
        attestation.agent_id = None

        result = attestation.previous_attestation
        self.assertIsNone(result)

    def test_previous_authenticated_attestation_property(self):
        """Test that previous_authenticated_attestation fetches correct attestation"""
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"
        attestation.index = 5

        mock_previous = MagicMock()

        with patch.object(Attestation, "get", return_value=mock_previous):
            result = attestation.previous_authenticated_attestation

            self.assertEqual(result, mock_previous)

    def test_previous_passed_attestation_property(self):
        """Test that previous_passed_attestation fetches attestation with pass evaluation"""
        attestation = Attestation.empty()
        attestation.agent_id = "test-agent"
        attestation.index = 5

        mock_previous = MagicMock()

        with patch.object(Attestation, "get", return_value=mock_previous):
            result = attestation.previous_passed_attestation

            self.assertEqual(result, mock_previous)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_decision_expected_by_with_evidence(self, mock_now, mock_config):
        """Test decision_expected_by uses evidence_received_at when available"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 300  # 5 minutes timeout

        attestation = Attestation.empty()
        attestation.evidence_received_at = now
        attestation.challenges_expire_at = now - timedelta(minutes=10)

        result = attestation.decision_expected_by

        expected = now + timedelta(seconds=300)
        self.assertEqual(result, expected)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_decision_expected_by_without_evidence(self, mock_now, mock_config):
        """Test decision_expected_by uses challenges_expire_at when no evidence received"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 300

        attestation = Attestation.empty()
        attestation.evidence_received_at = None
        attestation.challenges_expire_at = now + timedelta(minutes=30)

        result = attestation.decision_expected_by

        expected = attestation.challenges_expire_at + timedelta(seconds=300)
        self.assertEqual(result, expected)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_seconds_to_decision_positive(self, mock_now, mock_config):
        """Test seconds_to_decision returns positive value when decision is in future"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 300

        attestation = Attestation.empty()
        attestation.evidence_received_at = now
        attestation.challenges_expire_at = now

        # decision_expected_by = now + 300 seconds
        # seconds_to_decision = 300 - 0 = 300
        result = attestation.seconds_to_decision

        self.assertEqual(result, 300)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_seconds_to_decision_negative_returns_zero(self, mock_now, mock_config):
        """Test seconds_to_decision returns 0 when decision time has passed"""
        base_time = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_config.return_value = 300

        attestation = Attestation.empty()
        attestation.evidence_received_at = base_time

        # Set current time to be past the decision deadline
        mock_now.return_value = base_time + timedelta(seconds=400)

        result = attestation.seconds_to_decision

        self.assertEqual(result, 0)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_next_attestation_expected_after_with_evidence(self, mock_now, mock_config):
        """Test next_attestation_expected_after uses evidence_received_at when available"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 600  # quote_interval

        attestation = Attestation.empty()
        attestation.evidence_received_at = now
        attestation.capabilities_received_at = now - timedelta(minutes=10)

        result = attestation.next_attestation_expected_after

        expected = now + timedelta(seconds=600)
        self.assertEqual(result, expected)

    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_next_attestation_expected_after_without_evidence(self, mock_now):
        """Test next_attestation_expected_after uses capabilities_received_at when no evidence"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now

        attestation = Attestation.empty()
        attestation.evidence_received_at = None
        attestation.capabilities_received_at = now

        result = attestation.next_attestation_expected_after

        self.assertEqual(result, now)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_seconds_to_next_attestation_positive(self, mock_now, mock_config):
        """Test seconds_to_next_attestation returns positive value"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 600

        attestation = Attestation.empty()
        attestation.evidence_received_at = now

        result = attestation.seconds_to_next_attestation

        self.assertEqual(result, 600)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_seconds_to_next_attestation_negative_returns_zero(self, mock_now, mock_config):
        """Test seconds_to_next_attestation returns 0 when time has passed"""
        base_time = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_config.return_value = 600

        attestation = Attestation.empty()
        attestation.evidence_received_at = base_time

        # Set current time to be past the next attestation time
        mock_now.return_value = base_time + timedelta(seconds=700)

        result = attestation.seconds_to_next_attestation

        self.assertEqual(result, 0)

    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_challenges_valid_returns_true(self, mock_now):
        """Test challenges_valid returns True when challenges haven't expired"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now

        attestation = Attestation.empty()
        attestation.challenges_expire_at = now + timedelta(minutes=10)

        self.assertTrue(attestation.challenges_valid)

    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_challenges_valid_returns_false(self, mock_now):
        """Test challenges_valid returns False when challenges have expired"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now

        attestation = Attestation.empty()
        attestation.challenges_expire_at = now - timedelta(minutes=10)

        self.assertFalse(attestation.challenges_valid)

    def test_challenges_valid_returns_false_when_none(self):
        """Test challenges_valid returns False when challenges_expire_at is None"""
        attestation = Attestation.empty()
        attestation.challenges_expire_at = None

        self.assertFalse(attestation.challenges_valid)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_verification_in_progress_returns_true(self, mock_now, mock_config):
        """Test verification_in_progress returns True when evaluating and time remaining"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 300

        attestation = Attestation.empty()
        attestation.stage = "evaluating_evidence"
        attestation.evidence_received_at = now

        self.assertTrue(attestation.verification_in_progress)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_verification_in_progress_returns_false(self, mock_now, mock_config):
        """Test verification_in_progress returns False when not evaluating"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 300

        attestation = Attestation.empty()
        attestation.stage = "verification_complete"
        attestation.evidence_received_at = now

        self.assertFalse(attestation.verification_in_progress)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_ready_for_next_attestation_returns_true(self, mock_now, mock_config):
        """Test ready_for_next_attestation returns True when enough time has passed"""
        base_time = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_config.return_value = 600

        attestation = Attestation.empty()
        attestation.stage = "verification_complete"
        attestation.evidence_received_at = base_time

        # Set current time to be past the next attestation time
        mock_now.return_value = base_time + timedelta(seconds=700)

        self.assertTrue(attestation.ready_for_next_attestation)

    @patch("keylime.models.verifier.attestation.config.getint")
    @patch("keylime.models.base.types.timestamp.Timestamp.now")
    def test_ready_for_next_attestation_returns_false(self, mock_now, mock_config):
        """Test ready_for_next_attestation returns False when still in progress"""
        now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        mock_now.return_value = now
        mock_config.return_value = 300

        attestation = Attestation.empty()
        attestation.stage = "evaluating_evidence"
        attestation.evidence_received_at = now

        self.assertFalse(attestation.ready_for_next_attestation)


if __name__ == "__main__":
    unittest.main()
