"""Unit tests for AttestationController

This module tests the AttestationController class, specifically the parameter
handling in update() and update_latest() methods for push attestation.
"""

import unittest
from typing import cast
from unittest.mock import Mock, patch

from keylime.models.verifier.verifier_agent import VerifierAgent
from keylime.web.base.exceptions import StopAction
from keylime.web.verifier.attestation_controller import AttestationController


class TestAttestationControllerParameterHandling(unittest.TestCase):
    """Test parameter handling in AttestationController methods.

    These tests verify that the update() and update_latest() methods correctly
    handle parameters passed via **params dict (as done by the web framework)
    rather than as positional arguments.

    Without the fix, these methods would raise TypeError when called with
    attestation data in the params dict.
    """

    def setUp(self) -> None:
        """Set up test fixtures"""
        # Create a mock action_handler with minimal required attributes
        self.mock_action_handler = Mock()
        self.mock_action_handler.request = Mock()
        self.mock_action_handler.request.method = "PATCH"
        self.mock_action_handler.request.path = "/v3/agents/test-agent-123/attestations/1"
        self.mock_action_handler.request.headers = Mock()
        self.mock_action_handler.request.headers.get = Mock(return_value="application/vnd.api+json")
        self.mock_action_handler.request.headers.copy = Mock(return_value={})

        # Create the controller with the mock action_handler
        self.controller = cast(AttestationController, AttestationController(self.mock_action_handler))

        # Mock the api_request_body to satisfy the @require_json_api decorator
        # This simulates a valid JSON:API request
        self.controller._api_request_body = Mock()  # pylint: disable=protected-access

        self.agent_id = "test-agent-123"
        self.attestation_index = "1"  # String, as it comes from URL route

        # Mock attestation evidence data
        self.attestation_data = {
            "tpm_quote": {"quote": "mock_quote_data", "signature": "mock_signature"},
            "pcrs": {"0": "0" * 64},
        }

    @patch("keylime.web.verifier.attestation_controller.APIMessageBody")
    @patch("keylime.web.verifier.attestation_controller.EngineDriver")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_update_with_attestation_in_params(self, mock_agent_class, mock_engine_driver_class, mock_api_message_body):
        """Test update() when attestation is passed in **params dict.

        This reproduces the actual call pattern from the web framework where
        attestation data is extracted from the JSON:API request body and
        passed as params["attestation"].

        Without the fix: TypeError: update() missing 1 required positional
                        argument: 'attestation'
        With the fix: Should work correctly
        """
        # Setup mock agent and attestation
        mock_agent = Mock(spec=VerifierAgent)
        mock_attestation = Mock()
        mock_attestation.index = self.attestation_index
        mock_attestation.stage = "awaiting_evidence"
        mock_attestation.challenges_valid = True
        mock_attestation.changes_valid = True
        mock_attestation.commit_changes = Mock()
        mock_attestation.receive_evidence = Mock()
        mock_attestation.render_evidence_acknowledged = Mock(return_value={})
        mock_attestation.seconds_to_next_attestation = 60
        mock_agent.latest_attestation = mock_attestation
        mock_agent_class.get.return_value = mock_agent

        # Mock the EngineDriver
        mock_driver = Mock()
        mock_driver.process_evidence = Mock(return_value=mock_driver)
        mock_driver.verify_evidence = Mock()
        mock_engine_driver_class.return_value = mock_driver

        # Mock APIMessageBody to prevent actual response sending
        mock_message_body = Mock()
        mock_message_body.send_via = Mock()
        mock_api_message_body.return_value = mock_message_body

        # Call update() the way the web framework does - attestation in params
        # This would raise TypeError without the fix
        try:
            self.controller.update(
                self.agent_id, self.attestation_index, attestation=self.attestation_data  # Passed as keyword arg
            )
            # If we get here, the fix is working
            test_passed = True
        except TypeError as e:
            if "missing 1 required positional argument: 'attestation'" in str(e):
                self.fail("Bug reproduced: attestation parameter not extracted from **params")
            raise

        self.assertTrue(test_passed)
        mock_attestation.receive_evidence.assert_called_once_with(self.attestation_data)

    @patch("keylime.web.verifier.attestation_controller.APIError")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_update_with_missing_attestation(self, mock_agent_class, mock_api_error_class):
        """Test update() validates that attestation data is present.

        The fix should not only extract attestation from params, but also
        validate that it's not None and return proper error.
        """
        # Setup mock agent
        mock_agent = Mock(spec=VerifierAgent)
        mock_attestation = Mock()
        mock_attestation.index = self.attestation_index
        mock_attestation.stage = "awaiting_evidence"
        mock_attestation.challenges_valid = True
        mock_agent.latest_attestation = mock_attestation
        mock_agent_class.get.return_value = mock_agent

        # Mock APIError to prevent actual error sending
        mock_error = Mock()
        mock_error.set_detail = Mock(return_value=mock_error)
        mock_error.send_via = Mock(side_effect=StopAction)
        mock_api_error_class.return_value = mock_error

        # Call without attestation - should trigger validation error
        try:
            self.controller.update(
                self.agent_id,
                self.attestation_index,
                # No attestation parameter - should fail validation
            )
        except StopAction:
            pass  # Expected when error is sent

        # Verify error was created with correct parameters
        mock_api_error_class.assert_called_with("invalid_request", 400)
        mock_error.set_detail.assert_called_once()

    @patch("keylime.web.verifier.attestation_controller.APIError")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_update_with_nonexistent_agent(self, mock_agent_class, mock_api_error_class):
        """Test update() handles non-existent agent correctly"""
        # Return None to simulate agent not found
        mock_agent_class.get.return_value = None

        # Mock APIError to prevent actual error sending
        mock_error = Mock()
        mock_error.send_via = Mock(side_effect=StopAction)
        mock_api_error_class.return_value = mock_error

        # Call should trigger not_found error
        try:
            self.controller.update(self.agent_id, self.attestation_index, attestation=self.attestation_data)
        except StopAction:
            pass  # Expected when error is sent

        # Should create not_found error
        mock_api_error_class.assert_called()
        args = mock_api_error_class.call_args[0]
        self.assertEqual(args[0], "not_found")

    @patch("keylime.web.verifier.attestation_controller.APIMessageBody")
    @patch("keylime.web.verifier.attestation_controller.EngineDriver")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_update_latest_with_attestation_in_params(
        self, mock_agent_class, mock_engine_driver_class, mock_api_message_body
    ):
        """Test update_latest() when attestation is passed in **params dict.

        This tests that update_latest correctly passes the params dict
        to the update() method.

        Without the fix: Would fail when update() tries to use attestation
        With the fix: Should work correctly
        """
        # Setup mock agent and attestation
        mock_agent = Mock(spec=VerifierAgent)
        mock_attestation = Mock()
        mock_attestation.index = self.attestation_index
        mock_attestation.stage = "awaiting_evidence"
        mock_attestation.challenges_valid = True
        mock_attestation.changes_valid = True
        mock_attestation.commit_changes = Mock()
        mock_attestation.receive_evidence = Mock()
        mock_attestation.render_evidence_acknowledged = Mock(return_value={})
        mock_attestation.seconds_to_next_attestation = 60
        mock_agent.latest_attestation = mock_attestation
        mock_agent_class.get.return_value = mock_agent

        # Mock the EngineDriver
        mock_driver = Mock()
        mock_driver.process_evidence = Mock(return_value=mock_driver)
        mock_driver.verify_evidence = Mock()
        mock_engine_driver_class.return_value = mock_driver

        # Mock APIMessageBody to prevent actual response sending
        mock_message_body = Mock()
        mock_message_body.send_via = Mock()
        mock_api_message_body.return_value = mock_message_body

        # Call update_latest() with attestation in params
        try:
            self.controller.update_latest(self.agent_id, attestation=self.attestation_data)
            test_passed = True
        except TypeError as e:
            if "missing 1 required positional argument" in str(e):
                self.fail("Bug reproduced: update_latest not passing params correctly")
            raise

        self.assertTrue(test_passed)
        mock_attestation.receive_evidence.assert_called_once_with(self.attestation_data)

    @patch("keylime.web.verifier.attestation_controller.APIError")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_update_latest_with_no_attestation(self, mock_agent_class, mock_api_error_class):
        """Test update_latest() when agent has no latest attestation"""
        # Setup mock agent without attestation
        mock_agent = Mock(spec=VerifierAgent)
        mock_agent.latest_attestation = None
        mock_agent_class.get.return_value = mock_agent

        # Mock APIError to prevent actual error sending
        mock_error = Mock()
        mock_error.send_via = Mock(side_effect=StopAction)
        mock_api_error_class.return_value = mock_error

        # Call should trigger not_found error
        try:
            self.controller.update_latest(self.agent_id, attestation=self.attestation_data)
        except StopAction:
            pass  # Expected when error is sent

        # Should create not_found error
        mock_api_error_class.assert_called()
        args = mock_api_error_class.call_args[0]
        self.assertEqual(args[0], "not_found")


class TestAttestationControllerErrorMessages(unittest.TestCase):
    """Test error message handling when agent sends error reports.

    These tests verify that when a Rust agent sends an error message
    (type: "error" instead of type: "attestation"), the verifier properly
    rejects it with a meaningful error message.
    """

    def setUp(self) -> None:
        """Set up test fixtures"""
        # Create a mock action_handler with minimal required attributes
        self.mock_action_handler = Mock()
        self.mock_action_handler.request = Mock()
        self.mock_action_handler.request.method = "PATCH"
        self.mock_action_handler.request.path = "/v3/agents/test-agent-123/attestations/1"
        self.mock_action_handler.request.headers = Mock()
        self.mock_action_handler.request.headers.get = Mock(return_value="application/vnd.api+json")
        self.mock_action_handler.request.headers.copy = Mock(return_value={})

        # Create the controller with the mock action_handler
        self.controller = cast(AttestationController, AttestationController(self.mock_action_handler))

        # Mock the api_request_body to satisfy the @require_json_api decorator
        # This simulates a valid JSON:API request
        self.controller._api_request_body = Mock()  # pylint: disable=protected-access

        self.agent_id = "test-agent-123"
        self.attestation_index = "1"  # String, as it comes from URL route

    @patch("keylime.web.verifier.attestation_controller.APIError")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_update_rejects_error_message_from_agent(self, mock_agent_class, mock_api_error_class):
        """Test that error messages from agent are properly rejected.

        When a Rust agent fails to prepare evidence (e.g., missing UEFI log),
        it sends {"type": "error"} instead of {"type": "attestation"}.
        The verifier should reject this with a 400 error.
        """
        # Setup mock agent
        mock_agent = Mock(spec=VerifierAgent)
        mock_attestation = Mock()
        mock_attestation.index = self.attestation_index
        mock_attestation.stage = "awaiting_evidence"
        mock_attestation.challenges_valid = True
        mock_agent.latest_attestation = mock_attestation
        mock_agent_class.get.return_value = mock_agent

        # Mock APIError to prevent actual error sending
        mock_error = Mock()
        mock_error.set_detail = Mock(return_value=mock_error)
        mock_error.send_via = Mock(side_effect=StopAction)
        mock_api_error_class.return_value = mock_error

        # Agent sends error message (no attestation data)
        error_params = {
            "type": "error",
            "evidence_collected": [],
            # Note: No "attestation" key, which means params.get("attestation") returns None
        }

        # Call should trigger invalid_request error
        try:
            self.controller.update(self.agent_id, self.attestation_index, **error_params)  # No attestation key
        except StopAction:
            pass  # Expected when error is sent

        # Should reject with invalid_request
        mock_api_error_class.assert_called()
        args = mock_api_error_class.call_args[0]
        self.assertEqual(args[0], "invalid_request")
        self.assertEqual(args[1], 400)


class TestAttestationControllerExponentialBackoff(unittest.TestCase):
    """Test exponential backoff behavior when attestation fails.

    These tests verify that the verifier implements 503 Service Unavailable
    with exponential backoff when an agent retries after a failed attestation.
    """

    def setUp(self) -> None:
        """Set up test fixtures"""
        # Create a mock action_handler with minimal required attributes
        self.mock_action_handler = Mock()
        self.mock_action_handler.request = Mock()
        self.mock_action_handler.request.method = "POST"
        self.mock_action_handler.request.path = "/v3/agents/test-agent-123/attestations"
        self.mock_action_handler.request.headers = Mock()
        self.mock_action_handler.request.headers.get = Mock(return_value="application/vnd.api+json")
        self.mock_action_handler.request.headers.copy = Mock(return_value={})

        # Create the controller with the mock action_handler
        self.controller = cast(AttestationController, AttestationController(self.mock_action_handler))

        # Mock the api_request_body to satisfy the @require_json_api decorator
        self.controller._api_request_body = Mock()  # pylint: disable=protected-access

        self.agent_id = "test-agent-123"

    @patch("keylime.config.getint")
    @patch("keylime.common.retry.retry_time")
    @patch("keylime.web.verifier.attestation_controller.APIError")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_create_returns_503_after_failed_attestation(
        self, mock_agent_class, mock_api_error_class, mock_retry_time, mock_getint
    ):
        """Test that create() returns 503 Service Unavailable after a failed attestation.

        When the last attestation failed verification, the verifier should return
        503 with exponential backoff Retry-After header to prevent DoS.
        """
        # Setup mock agent with failed latest attestation
        mock_agent = Mock(spec=VerifierAgent)
        mock_agent.accept_attestations = True
        mock_agent.consecutive_attestation_failures = 2

        mock_attestation = Mock()
        mock_attestation.evaluation = "fail"
        mock_attestation.stage = "verification_complete"
        mock_agent.latest_attestation = mock_attestation
        mock_agent_class.get.return_value = mock_agent

        # Mock config value for quote_interval (max cap)
        mock_getint.return_value = 100  # High enough that it won't cap our retry value

        # Mock retry calculation to return predictable value
        mock_retry_time.return_value = 8.0  # 2nd retry with exponential backoff

        # Mock APIError to prevent actual error sending
        mock_error = Mock()
        mock_error.set_detail = Mock(return_value=mock_error)
        mock_error.send_via = Mock(side_effect=StopAction)
        mock_api_error_class.return_value = mock_error

        # Mock set_header to verify Retry-After is set
        self.controller.set_header = Mock()

        # Call should trigger 503 error
        try:
            self.controller.create(self.agent_id, attestation={})
        except StopAction:
            pass  # Expected when error is sent

        # Should set Retry-After header with exponential backoff value
        self.controller.set_header.assert_called_once_with("Retry-After", "8")

        # Should create 503 error
        mock_api_error_class.assert_called_with("attestation_failed_retry", 503)
        mock_error.set_detail.assert_called_once()

    @patch("keylime.config.getint")
    @patch("keylime.common.retry.retry_time")
    @patch("keylime.web.verifier.attestation_controller.APIError")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_create_uses_consecutive_failures_for_backoff(
        self, mock_agent_class, mock_api_error_class, mock_retry_time, mock_getint
    ):
        """Test that consecutive failure count is used for exponential backoff calculation.

        The retry delay should increase based on the number of consecutive failures.
        """
        # Setup mock agent with multiple consecutive failures
        mock_agent = Mock(spec=VerifierAgent)
        mock_agent.accept_attestations = True
        mock_agent.consecutive_attestation_failures = 5

        mock_attestation = Mock()
        mock_attestation.evaluation = "fail"
        mock_attestation.stage = "verification_complete"
        mock_agent.latest_attestation = mock_attestation
        mock_agent_class.get.return_value = mock_agent

        # Mock config value for quote_interval (max cap)
        mock_getint.return_value = 100  # High enough that it won't cap our retry value

        # Mock retry calculation
        mock_retry_time.return_value = 32.0

        # Mock APIError to prevent actual error sending
        mock_error = Mock()
        mock_error.set_detail = Mock(return_value=mock_error)
        mock_error.send_via = Mock(side_effect=StopAction)
        mock_api_error_class.return_value = mock_error

        # Mock set_header
        self.controller.set_header = Mock()

        # Call should trigger 503 error
        try:
            self.controller.create(self.agent_id, attestation={})
        except StopAction:
            pass

        # Verify retry_time was called with consecutive failures count
        mock_retry_time.assert_called_once()
        call_args = mock_retry_time.call_args[0]
        self.assertEqual(call_args[2], 5)  # consecutive_failures parameter

    @patch("keylime.config.getint")
    @patch("keylime.common.retry.retry_time")
    @patch("keylime.web.verifier.attestation_controller.APIError")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_create_caps_retry_after_at_quote_interval(
        self, mock_agent_class, mock_api_error_class, mock_retry_time, mock_getint
    ):
        """Test that Retry-After is capped at quote_interval to prevent excessive delays.

        Even with many consecutive failures, the retry delay should not exceed
        the configured quote_interval.
        """
        # Setup mock agent with many consecutive failures
        mock_agent = Mock(spec=VerifierAgent)
        mock_agent.accept_attestations = True
        mock_agent.consecutive_attestation_failures = 10

        mock_attestation = Mock()
        mock_attestation.evaluation = "fail"
        mock_attestation.stage = "verification_complete"
        mock_agent.latest_attestation = mock_attestation
        mock_agent_class.get.return_value = mock_agent

        # Mock config value for quote_interval (max cap) - set to 60 to test capping
        mock_getint.return_value = 60

        # Mock retry calculation to return a very high value
        mock_retry_time.return_value = 1024.0

        # Mock APIError to prevent actual error sending
        mock_error = Mock()
        mock_error.set_detail = Mock(return_value=mock_error)
        mock_error.send_via = Mock(side_effect=StopAction)
        mock_api_error_class.return_value = mock_error

        # Mock set_header
        self.controller.set_header = Mock()

        # Call should trigger 503 error
        try:
            self.controller.create(self.agent_id, attestation={})
        except StopAction:
            pass

        # Should cap at max_interval (quote_interval config = 60)
        # The actual retry_after should be min(1024, 60) = 60
        self.controller.set_header.assert_called_once_with("Retry-After", "60")

    @patch("keylime.web.verifier.attestation_controller.Attestation")
    @patch("keylime.web.verifier.attestation_controller.EngineDriver")
    @patch("keylime.web.verifier.attestation_controller.VerifierAgent")
    def test_create_succeeds_when_no_failed_attestation(
        self, mock_agent_class, mock_engine_driver_class, mock_attestation_class
    ):
        """Test that create() succeeds when last attestation passed or doesn't exist.

        The exponential backoff should only apply when the last attestation failed.
        """
        # Setup mock agent with passing attestation
        mock_agent = Mock(spec=VerifierAgent)
        mock_agent.accept_attestations = True
        mock_agent.consecutive_attestation_failures = 0

        mock_attestation = Mock()
        mock_attestation.evaluation = "pass"  # Not failed
        mock_attestation.stage = "verification_complete"
        mock_attestation.verification_in_progress = False
        mock_attestation.ready_for_next_attestation = True
        mock_agent.latest_attestation = mock_attestation
        mock_agent_class.get.return_value = mock_agent

        # Mock new attestation creation
        mock_new_attestation = Mock()
        mock_new_attestation.index = 42
        mock_new_attestation.changes_valid = True
        mock_new_attestation.commit_changes = Mock()
        mock_new_attestation.receive_capabilities = Mock()
        mock_new_attestation.render_evidence_requested = Mock(return_value={})
        mock_attestation_class.create.return_value = mock_new_attestation

        # Mock EngineDriver
        mock_driver = Mock()
        mock_driver.process_capabilities = Mock()
        mock_engine_driver_class.return_value = mock_driver

        # Mock APIResource and APILink to prevent actual response sending
        with patch("keylime.web.verifier.attestation_controller.APIResource") as mock_resource:
            with patch("keylime.web.verifier.attestation_controller.APILink"):
                mock_resource_instance = Mock()
                mock_resource_instance.include = Mock(return_value=mock_resource_instance)
                mock_resource_instance.send_via = Mock()
                mock_resource.return_value = mock_resource_instance

                # Should succeed without triggering 503
                self.controller.create(self.agent_id, attestation={})

                # Verify new attestation was created
                mock_attestation_class.create.assert_called_once()


class TestAttestationRecovery(unittest.TestCase):
    """Test that PUSH mode agents can recover from timeout-induced failures"""

    def setUp(self) -> None:
        """Set up test fixtures"""
        self.mock_action_handler = Mock()
        self.mock_action_handler.request = Mock()
        self.mock_action_handler.request.method = "POST"
        self.mock_action_handler.request.path = "/v3/agents/test-agent/attestations"
        self.mock_action_handler.request.headers = Mock()
        self.mock_action_handler.request.headers.get = Mock(return_value="application/vnd.api+json")
        self.mock_action_handler.request.headers.copy = Mock(return_value={})

        self.controller = cast(AttestationController, AttestationController(self.mock_action_handler))
        self.controller._api_request_body = Mock()  # pylint: disable=protected-access

    @patch("keylime.web.verifier.attestation_controller.agent_util.is_push_mode_agent")
    @patch("keylime.models.verifier.verifier_agent.VerifierAgent.get")
    def test_push_mode_agent_can_attest_when_disabled(self, mock_get, mock_is_push_mode):
        """PUSH mode agents should be allowed to attest even when accept_attestations=False"""
        # Create a PUSH mode agent with attestations disabled (simulating timeout)
        mock_agent = Mock(spec=VerifierAgent)
        mock_agent.agent_id = "test-push-agent"
        mock_agent.accept_attestations = False  # Disabled due to timeout
        mock_agent.ip = None  # PUSH mode
        mock_agent.port = None  # PUSH mode
        mock_agent.latest_attestation = None  # No previous attestations

        mock_get.return_value = mock_agent
        mock_is_push_mode.return_value = True

        # Mock Attestation.create to prevent actual database operations
        with patch("keylime.models.verifier.Attestation.create") as mock_attestation_create:
            # Mock the attestation record
            mock_attestation_record = Mock()
            mock_attestation_record.index = 0
            mock_attestation_record.changes_valid = True
            mock_attestation_record.receive_capabilities = Mock()
            mock_attestation_record.commit_changes = Mock()
            mock_attestation_record.render_evidence_requested = Mock(return_value={})
            mock_attestation_create.return_value = mock_attestation_record

            # Mock EngineDriver
            with patch("keylime.web.verifier.attestation_controller.EngineDriver") as mock_engine:
                mock_engine.return_value.process_capabilities = Mock()

                with patch("keylime.web.verifier.attestation_controller.APIResource") as mock_resource:
                    mock_resource_instance = Mock()
                    mock_resource_instance.include = Mock(return_value=mock_resource_instance)
                    mock_resource_instance.send_via = Mock()
                    mock_resource.return_value = mock_resource_instance

                    with patch("keylime.web.verifier.attestation_controller.APILink"):
                        # This should NOT raise StopAction with 403 for PUSH mode agents
                        # (even though accept_attestations=False)
                        # If create() succeeds, the agent was allowed to attest (correct!)
                        self.controller.create("test-push-agent", attestation={})

    @patch("keylime.web.verifier.attestation_controller.agent_util.is_push_mode_agent")
    @patch("keylime.models.verifier.verifier_agent.VerifierAgent.get")
    def test_pull_mode_agent_rejected_when_disabled(self, mock_get, mock_is_push_mode):
        """PULL mode agents should be rejected when accept_attestations=False"""
        # Create a PULL mode agent with attestations disabled
        mock_agent = Mock(spec=VerifierAgent)
        mock_agent.agent_id = "test-pull-agent"
        mock_agent.accept_attestations = False  # Disabled due to failure
        mock_agent.ip = "127.0.0.1"  # PULL mode
        mock_agent.port = 9002  # PULL mode

        mock_get.return_value = mock_agent
        mock_is_push_mode.return_value = False

        # This SHOULD raise StopAction for PULL mode agents
        # (The logged message confirms it's agent_attestations_disabled 403 error)
        with self.assertRaises(StopAction):
            self.controller.create("test-pull-agent", attestation={})


if __name__ == "__main__":
    unittest.main()
