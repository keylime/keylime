"""
Unit tests for keylime.verification.tpm_engine module
"""

# pylint: disable=protected-access,attribute-defined-outside-init
# Testing requires access to protected methods and dynamic test attributes

import unittest
from unittest.mock import MagicMock, PropertyMock, patch

from keylime.failure import Component, Failure
from keylime.verification.tpm_engine import TPMEngine


class TestTPMEngineProcessResults(unittest.TestCase):
    """Tests for TPMEngine._process_results method behavior"""

    def setUp(self):
        """Set up test fixtures"""
        # Create mock attestation with required attributes
        self.mock_attestation = MagicMock()
        self.mock_attestation.agent_id = "test-agent-123"
        self.mock_attestation.evaluation = None
        self.mock_attestation.system_info = None
        self.mock_attestation.evidence = MagicMock()

        # Mock evidence view to return empty results
        mock_view = MagicMock()
        mock_view.filter.return_value = mock_view
        mock_view.result.return_value = []
        self.mock_attestation.evidence.view.return_value = mock_view

        # Create mock agent with required attributes
        self.mock_agent = MagicMock()
        self.mock_agent.agent_id = "test-agent-123"
        self.mock_agent.attestation_count = 0
        self.mock_agent.accept_attestations = True
        self.mock_agent.ima_policy = None
        self.mock_agent.mb_policy = None
        self.mock_agent.tpm_policy = {}
        self.mock_agent.ak_tpm = "mock-ak"
        self.mock_agent.accept_tpm_signing_algs = []
        self.mock_agent.accept_tpm_hash_algs = []

        self.mock_attestation.agent = self.mock_agent

        # Create engine instance
        self.engine = TPMEngine(self.mock_attestation)

    @patch("keylime.verification.tpm_engine.config.get")
    @patch("keylime.verification.tpm_engine.config.getboolean")
    @patch("keylime.verification.tpm_engine.AuthSession.delete_active_session_for_agent")
    def test_process_results_push_mode_failure_preserves_session(
        self, mock_delete_session, mock_getboolean, mock_config_get
    ):
        """In push mode, failed attestation should preserve auth session"""
        # Configure mocks
        mock_config_get.return_value = "push"  # Push mode
        mock_getboolean.return_value = True  # extend_token_on_attestation

        # Create a failure
        failure = Failure(Component.QUOTE_VALIDATION)
        failure.add_event("test_failure", "Test failure", True)

        # Mock all required methods and properties
        with patch.object(self.engine, "_select_ima_log_item", return_value=None):
            with patch.object(self.engine, "_determine_failure_reason"):
                with patch.object(type(self.engine), "attest_state", new_callable=PropertyMock, return_value=None):
                    with patch.object(
                        type(self.engine), "failure_reason", new_callable=PropertyMock, return_value=None
                    ):
                        # Process results with failure
                        self.engine._process_results(failure)

        # In push mode, session should NOT be deleted
        mock_delete_session.assert_not_called()

        # accept_attestations should remain True in push mode
        self.assertTrue(self.mock_agent.accept_attestations)

        # Evaluation should be set to fail
        self.assertEqual(self.mock_attestation.evaluation, "fail")

    @patch("keylime.verification.tpm_engine.config.get")
    @patch("keylime.verification.tpm_engine.config.getboolean")
    @patch("keylime.verification.tpm_engine.AuthSession.delete_active_session_for_agent")
    def test_process_results_pull_mode_failure_deletes_session(
        self, mock_delete_session, mock_getboolean, mock_config_get
    ):
        """In pull mode, failed attestation should delete auth session"""
        # Configure mocks
        mock_config_get.return_value = "pull"  # Pull mode
        mock_getboolean.return_value = True  # extend_token_on_attestation

        # Create a failure
        failure = Failure(Component.QUOTE_VALIDATION)
        failure.add_event("test_failure", "Test failure", True)

        # Mock all required methods and properties
        with patch.object(self.engine, "_select_ima_log_item", return_value=None):
            with patch.object(self.engine, "_determine_failure_reason"):
                with patch.object(type(self.engine), "attest_state", new_callable=PropertyMock, return_value=None):
                    with patch.object(
                        type(self.engine), "failure_reason", new_callable=PropertyMock, return_value=None
                    ):
                        # Process results with failure
                        self.engine._process_results(failure)

        # In pull mode, session SHOULD be deleted
        mock_delete_session.assert_called_once_with("test-agent-123")

        # accept_attestations should be set to False in pull mode
        self.assertFalse(self.mock_agent.accept_attestations)

        # Evaluation should be set to fail
        self.assertEqual(self.mock_attestation.evaluation, "fail")

    @patch("keylime.verification.tpm_engine.config.getboolean")
    def test_process_results_success_extends_token(self, mock_getboolean):
        """Successful attestation should extend auth token"""
        # Configure mocks
        mock_getboolean.return_value = True  # extend_token_on_attestation

        # Mock _extend_auth_token
        with patch.object(self.engine, "_extend_auth_token") as mock_extend:
            with patch.object(self.engine, "_select_ima_log_item", return_value=None):
                with patch.object(self.engine, "_determine_failure_reason"):
                    with patch.object(type(self.engine), "attest_state", new_callable=PropertyMock, return_value=None):
                        with patch.object(
                            type(self.engine), "failure_reason", new_callable=PropertyMock, return_value=None
                        ):
                            # Process results with no failure (success)
                            self.engine._process_results(None)

            # Token should be extended on success
            mock_extend.assert_called_once()

        # Attestation count should increment
        self.assertEqual(self.mock_agent.attestation_count, 1)

        # Evaluation should be set to pass
        self.assertEqual(self.mock_attestation.evaluation, "pass")

    @patch("keylime.verification.tpm_engine.config.getboolean")
    def test_process_results_success_no_extend_when_disabled(self, mock_getboolean):
        """Successful attestation should not extend token when disabled"""
        # Configure mocks
        mock_getboolean.return_value = False  # extend_token_on_attestation disabled

        # Mock _extend_auth_token
        with patch.object(self.engine, "_extend_auth_token") as mock_extend:
            with patch.object(self.engine, "_select_ima_log_item", return_value=None):
                with patch.object(self.engine, "_determine_failure_reason"):
                    with patch.object(type(self.engine), "attest_state", new_callable=PropertyMock, return_value=None):
                        with patch.object(
                            type(self.engine), "failure_reason", new_callable=PropertyMock, return_value=None
                        ):
                            # Process results with no failure (success)
                            self.engine._process_results(None)

            # Token should NOT be extended when disabled
            mock_extend.assert_not_called()

        # Attestation count should still increment
        self.assertEqual(self.mock_agent.attestation_count, 1)

        # Evaluation should be set to pass
        self.assertEqual(self.mock_attestation.evaluation, "pass")

    @patch("keylime.verification.tpm_engine.config.get")
    @patch("keylime.verification.tpm_engine.config.getboolean")
    @patch("keylime.verification.tpm_engine.AuthSession.delete_active_session_for_agent")
    def test_process_results_failure_does_not_extend_token(
        self, _mock_delete_session, mock_getboolean, mock_config_get
    ):
        """Failed attestation should never extend auth token"""
        # Configure mocks for push mode
        mock_config_get.return_value = "push"
        mock_getboolean.return_value = True  # extend_token_on_attestation enabled

        # Create a failure
        failure = Failure(Component.QUOTE_VALIDATION)
        failure.add_event("test_failure", "Test failure", True)

        # Mock _extend_auth_token
        with patch.object(self.engine, "_extend_auth_token") as mock_extend:
            with patch.object(self.engine, "_select_ima_log_item", return_value=None):
                with patch.object(self.engine, "_determine_failure_reason"):
                    with patch.object(type(self.engine), "attest_state", new_callable=PropertyMock, return_value=None):
                        with patch.object(
                            type(self.engine), "failure_reason", new_callable=PropertyMock, return_value=None
                        ):
                            # Process results with failure
                            self.engine._process_results(failure)

            # Token should NOT be extended on failure, even if enabled
            mock_extend.assert_not_called()

        # Evaluation should be set to fail
        self.assertEqual(self.mock_attestation.evaluation, "fail")


class TestTPMEngineFreshPolicy(unittest.TestCase):
    """Tests for TPMEngine fresh policy loading"""

    def setUp(self):
        """Set up test fixtures"""
        # Create mock attestation with required attributes
        self.mock_attestation = MagicMock()
        self.mock_attestation.agent_id = "test-agent-123"
        self.mock_attestation.system_info = None
        self.mock_attestation.evidence = MagicMock()

        # Mock evidence view to return empty results
        mock_view = MagicMock()
        mock_view.filter.return_value = mock_view
        mock_view.result.return_value = []
        self.mock_attestation.evidence.view.return_value = mock_view

        # Create mock agent with IMA policy
        self.mock_agent = MagicMock()
        self.mock_agent.agent_id = "test-agent-123"
        self.mock_agent.ima_policy = MagicMock()
        self.mock_agent.ima_policy.ima_policy = {"verification-keys": "old-keys", "version": 1}
        self.mock_agent.ima_policy_id = 42
        self.mock_agent.mb_policy = None
        self.mock_agent.tpm_policy = {}
        self.mock_agent.ak_tpm = "mock-ak"
        self.mock_agent.accept_tpm_signing_algs = []
        self.mock_agent.accept_tpm_hash_algs = []

        self.mock_attestation.agent = self.mock_agent

        # Create engine instance
        self.engine = TPMEngine(self.mock_attestation)

    @patch("keylime.models.base.db_manager.session_context")
    def test_ima_policy_reload_bypasses_cache(self, mock_session_context):
        """Test that ima_policy property reloads fresh policy from database"""
        # Create a fresh agent with updated policy ID
        fresh_agent = MagicMock()
        fresh_agent.ima_policy_id = 43  # Different ID indicates policy was updated

        # Mock database query result with new policy
        mock_result = MagicMock()
        mock_result.fetchone.return_value = ['{"verification-keys": "new-keys", "version": 2}']
        mock_session = MagicMock()
        mock_session.execute.return_value = mock_result
        mock_session_context.return_value.__enter__.return_value = mock_session

        # Simulate verify_evidence() reloading the agent
        self.engine._fresh_agent = fresh_agent  # pylint: disable=attribute-defined-outside-init

        # Access the ima_policy property
        policy = self.engine.ima_policy

        # Verify the fresh policy from database was used, not the cached one
        self.assertEqual(policy["verification-keys"], "new-keys")
        self.assertEqual(policy["version"], 2)

        # Verify raw SQL query was executed to bypass ORM cache
        mock_session.execute.assert_called_once()

    def test_ima_policy_uses_cached_when_no_fresh_agent(self):
        """Test that ima_policy falls back to cached policy when no fresh agent"""
        # Access the ima_policy property without setting _fresh_agent
        policy = self.engine.ima_policy

        # Verify the cached policy from the original agent was used
        self.assertEqual(policy["verification-keys"], "old-keys")
        self.assertEqual(policy["version"], 1)

    def test_agent_property_uses_fresh_agent_when_available(self):
        """Test that agent property returns fresh agent when available"""
        # Create a fresh agent
        fresh_agent = MagicMock()
        fresh_agent.agent_id = "test-agent-123"
        fresh_agent.attestation_count = 5  # Different from original

        # Simulate verify_evidence() reloading the agent
        self.engine._fresh_agent = fresh_agent  # pylint: disable=attribute-defined-outside-init

        # Access the agent property
        agent = self.engine.agent

        # Verify the fresh agent was returned
        self.assertEqual(agent.attestation_count, 5)
        self.assertIs(agent, fresh_agent)


if __name__ == "__main__":
    unittest.main()
