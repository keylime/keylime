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


if __name__ == "__main__":
    unittest.main()
