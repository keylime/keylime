"""Unit tests for AgentsController (registrar).

Tests the registrar's agent registration endpoints, including the
security fix that prevents UUID spoofing via re-registration with
a different TPM identity.
"""

# type: ignore - Controller methods are dynamically bound

import unittest
from typing import cast
from unittest.mock import MagicMock, patch

from keylime.web.registrar.agents_controller import AgentsController


class TestAgentsControllerIndex(unittest.TestCase):
    """Test cases for AgentsController.index()."""

    def setUp(self):
        """Set up test fixtures."""
        mock_action_handler = MagicMock()
        self.controller = cast(AgentsController, AgentsController(mock_action_handler))
        self.controller.respond = MagicMock()

    @patch("keylime.models.RegistrarAgent.all_ids")
    def test_index_success(self, mock_all_ids):
        """Test successful retrieval of all agent IDs."""
        mock_all_ids.return_value = ["agent-1", "agent-2", "agent-3"]

        self.controller.index()

        self.controller.respond.assert_called_once_with(200, "Success", {"uuids": ["agent-1", "agent-2", "agent-3"]})  # type: ignore[attr-defined]


class TestAgentsControllerShow(unittest.TestCase):
    """Test cases for AgentsController.show()."""

    def setUp(self):
        """Set up test fixtures."""
        mock_action_handler = MagicMock()
        self.controller = cast(AgentsController, AgentsController(mock_action_handler))
        self.controller.respond = MagicMock()
        self.test_agent_id = "test-agent-123"

    @patch("keylime.models.RegistrarAgent.get")
    def test_show_not_found(self, mock_get):
        """Test show with non-existent agent."""
        mock_get.return_value = None

        self.controller.show(self.test_agent_id)

        self.controller.respond.assert_called_once_with(404, f"Agent with ID '{self.test_agent_id}' not found")  # type: ignore[attr-defined]

    @patch("keylime.models.RegistrarAgent.get")
    def test_show_not_active(self, mock_get):
        """Test show with inactive agent."""
        mock_agent = MagicMock()
        mock_agent.active = False
        mock_get.return_value = mock_agent

        self.controller.show(self.test_agent_id)

        self.controller.respond.assert_called_once_with(  # type: ignore[attr-defined]
            404, f"Agent with ID '{self.test_agent_id}' has not been activated"
        )

    @patch("keylime.models.RegistrarAgent.get")
    def test_show_success(self, mock_get):
        """Test successful show of active agent."""
        mock_agent = MagicMock()
        mock_agent.active = True
        mock_agent.render.return_value = {"agent_id": self.test_agent_id, "active": True}
        mock_get.return_value = mock_agent

        self.controller.show(self.test_agent_id)

        self.controller.respond.assert_called_once_with(  # type: ignore[attr-defined]
            200, "Success", {"agent_id": self.test_agent_id, "active": True}
        )


class TestAgentsControllerCreate(unittest.TestCase):
    """Test cases for AgentsController.create() - the main registration endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        mock_action_handler = MagicMock()
        self.controller = cast(AgentsController, AgentsController(mock_action_handler))
        self.controller.respond = MagicMock()
        self.controller.log_model_errors = MagicMock()
        self.test_agent_id = "test-agent-123"

    @patch("keylime.models.RegistrarAgent.get")
    def test_create_new_agent_success(self, mock_get):
        """Test successful registration of a new agent."""
        # Mock that agent doesn't exist yet
        mock_get.return_value = None

        # Create mock agent that will be returned by empty()
        mock_agent = MagicMock()
        mock_agent.changes_valid = True
        mock_agent.errors = {}
        mock_agent.produce_ak_challenge.return_value = "challenge_blob_data"

        # Patch RegistrarAgent.empty to return our mock
        with patch("keylime.models.RegistrarAgent.empty", return_value=mock_agent):
            params = {"ek_tpm": "ek_key", "aik_tpm": "aik_key"}
            self.controller.create(self.test_agent_id, **params)

        # Verify agent was updated with params
        mock_agent.update.assert_called_once_with({"agent_id": self.test_agent_id, **params})

        # Verify challenge was generated
        mock_agent.produce_ak_challenge.assert_called_once()

        # Verify agent was saved
        mock_agent.commit_changes.assert_called_once()

        # Verify 200 response with challenge
        self.controller.respond.assert_called_once_with(200, "Success", {"blob": "challenge_blob_data"})  # type: ignore[attr-defined]

    @patch("keylime.models.RegistrarAgent.get")
    def test_create_reregistration_same_tpm_identity(self, mock_get):
        """Test successful re-registration with same TPM identity."""
        # Mock existing agent
        mock_existing_agent = MagicMock()
        mock_existing_agent.changes_valid = True
        mock_existing_agent.errors = {}
        mock_existing_agent.produce_ak_challenge.return_value = "challenge_blob_data"
        mock_get.return_value = mock_existing_agent

        params = {"ek_tpm": "same_ek_key", "aik_tpm": "same_aik_key"}
        self.controller.create(self.test_agent_id, **params)

        # Verify agent was updated
        mock_existing_agent.update.assert_called_once_with({"agent_id": self.test_agent_id, **params})

        # Verify challenge was generated
        mock_existing_agent.produce_ak_challenge.assert_called_once()

        # Verify agent was saved
        mock_existing_agent.commit_changes.assert_called_once()

        # Verify 200 response
        self.controller.respond.assert_called_once_with(200, "Success", {"blob": "challenge_blob_data"})  # type: ignore[attr-defined]

    @patch("keylime.models.RegistrarAgent.get")
    def test_create_reregistration_different_tpm_identity_forbidden(self, mock_get):
        """Test re-registration with different TPM identity is rejected with 403.

        This is the key security fix: preventing UUID spoofing by rejecting
        attempts to re-register an agent with a different TPM identity.
        """
        # Mock existing agent
        mock_existing_agent = MagicMock()
        mock_existing_agent.changes_valid = False  # Validation failed
        # Simulate the error added by _check_tpm_identity_immutable
        mock_existing_agent.errors = {
            "agent_id": [
                "Agent re-registration attempted with different TPM identity (changed fields: ek_tpm). "
                "This is a security violation - the same agent UUID cannot be reused with a different TPM."
            ]
        }
        mock_get.return_value = mock_existing_agent

        params = {"ek_tpm": "different_ek_key", "aik_tpm": "same_aik_key"}
        self.controller.create(self.test_agent_id, **params)

        # Verify agent was updated (which triggers validation)
        mock_existing_agent.update.assert_called_once_with({"agent_id": self.test_agent_id, **params})

        # Verify errors were logged
        self.controller.log_model_errors.assert_called_once()  # type: ignore[attr-defined]

        # Verify 403 Forbidden response (not 400!)
        self.controller.respond.assert_called_once_with(  # type: ignore[attr-defined]
            403, "Agent re-registration with different TPM identity is forbidden for security reasons"
        )

        # Verify agent was NOT saved
        mock_existing_agent.commit_changes.assert_not_called()

    @patch("keylime.models.RegistrarAgent.get")
    def test_create_invalid_data_other_validation_error(self, mock_get):
        """Test registration with other validation errors returns 400."""
        # Mock agent with validation errors (not TPM identity related)
        mock_agent = MagicMock()
        mock_agent.changes_valid = False
        # Error not related to TPM identity
        mock_agent.errors = {"ek_tpm": ["must be a valid TPM2B_PUBLIC structure"]}
        mock_agent.produce_ak_challenge.return_value = None
        mock_get.return_value = None

        with patch("keylime.models.RegistrarAgent.empty", return_value=mock_agent):
            params = {"ek_tpm": "invalid_ek_format"}
            self.controller.create(self.test_agent_id, **params)

        # Verify errors were logged
        self.controller.log_model_errors.assert_called_once()  # type: ignore[attr-defined]

        # Verify 400 Bad Request (not 403)
        self.controller.respond.assert_called_once_with(400, "Could not register agent with invalid data")  # type: ignore[attr-defined]

        # Verify agent was NOT saved
        mock_agent.commit_changes.assert_not_called()

    @patch("keylime.models.RegistrarAgent.get")
    def test_create_challenge_generation_failure(self, mock_get):
        """Test registration fails if challenge generation fails."""
        # Mock agent where challenge generation fails
        mock_agent = MagicMock()
        mock_agent.changes_valid = True
        mock_agent.errors = {}
        mock_agent.produce_ak_challenge.return_value = None  # Challenge generation failed
        mock_get.return_value = None

        with patch("keylime.models.RegistrarAgent.empty", return_value=mock_agent):
            params = {"ek_tpm": "ek_key", "aik_tpm": "aik_key"}
            self.controller.create(self.test_agent_id, **params)

        # Verify errors were logged
        self.controller.log_model_errors.assert_called_once()  # type: ignore[attr-defined]

        # Verify 400 response
        self.controller.respond.assert_called_once_with(400, "Could not register agent with invalid data")  # type: ignore[attr-defined]

        # Verify agent was NOT saved
        mock_agent.commit_changes.assert_not_called()

    @patch("keylime.models.RegistrarAgent.get")
    def test_create_validation_error_with_agent_id_but_not_tpm_identity(self, mock_get):
        """Test that agent_id errors unrelated to TPM identity get 400, not 403."""
        # Mock agent with agent_id error, but not about TPM identity
        mock_agent = MagicMock()
        mock_agent.changes_valid = False
        mock_agent.errors = {"agent_id": ["must be a valid UUID format"]}  # Not about TPM identity
        mock_agent.produce_ak_challenge.return_value = None
        mock_get.return_value = None

        with patch("keylime.models.RegistrarAgent.empty", return_value=mock_agent):
            params = {"ek_tpm": "ek_key", "aik_tpm": "aik_key"}
            self.controller.create(self.test_agent_id, **params)

        # Verify 400 Bad Request (not 403) because it's not a TPM identity violation
        self.controller.respond.assert_called_once_with(400, "Could not register agent with invalid data")  # type: ignore[attr-defined]


class TestAgentsControllerDelete(unittest.TestCase):
    """Test cases for AgentsController.delete()."""

    def setUp(self):
        """Set up test fixtures."""
        mock_action_handler = MagicMock()
        self.controller = cast(AgentsController, AgentsController(mock_action_handler))
        self.controller.respond = MagicMock()
        self.test_agent_id = "test-agent-123"

    @patch("keylime.models.RegistrarAgent.get")
    def test_delete_not_found(self, mock_get):
        """Test delete with non-existent agent."""
        mock_get.return_value = None

        self.controller.delete(self.test_agent_id)

        self.controller.respond.assert_called_once_with(404, f"Agent with ID '{self.test_agent_id}' not found")  # type: ignore[attr-defined]

    @patch("keylime.models.RegistrarAgent.get")
    def test_delete_success(self, mock_get):
        """Test successful agent deletion."""
        mock_agent = MagicMock()
        mock_get.return_value = mock_agent

        self.controller.delete(self.test_agent_id)

        # Verify agent was deleted
        mock_agent.delete.assert_called_once()

        # Verify 200 response
        self.controller.respond.assert_called_once_with(200, "Success")  # type: ignore[attr-defined]


class TestAgentsControllerActivate(unittest.TestCase):
    """Test cases for AgentsController.activate()."""

    def setUp(self):
        """Set up test fixtures."""
        mock_action_handler = MagicMock()
        self.controller = cast(AgentsController, AgentsController(mock_action_handler))
        self.controller.respond = MagicMock()
        self.test_agent_id = "test-agent-123"
        self.test_auth_tag = "valid_auth_tag"

    @patch("keylime.models.RegistrarAgent.get")
    def test_activate_not_found(self, mock_get):
        """Test activate with non-existent agent."""
        mock_get.return_value = None

        self.controller.activate(self.test_agent_id, self.test_auth_tag)

        self.controller.respond.assert_called_once_with(404, f"Agent with ID '{self.test_agent_id}' not found")  # type: ignore[attr-defined]

    @patch("keylime.models.RegistrarAgent.get")
    def test_activate_success(self, mock_get):
        """Test successful agent activation."""
        mock_agent = MagicMock()
        mock_agent.verify_ak_response.return_value = True  # Auth tag is valid
        mock_get.return_value = mock_agent

        self.controller.activate(self.test_agent_id, self.test_auth_tag)

        # Verify auth tag was verified
        mock_agent.verify_ak_response.assert_called_once_with(self.test_auth_tag)

        # Verify agent was saved
        mock_agent.commit_changes.assert_called_once()

        # Verify 200 response
        self.controller.respond.assert_called_once_with(200, "Success")  # type: ignore[attr-defined]

    @patch("keylime.models.RegistrarAgent.get")
    def test_activate_invalid_auth_tag(self, mock_get):
        """Test activation with invalid auth tag."""
        mock_agent = MagicMock()
        mock_agent.verify_ak_response.return_value = False  # Auth tag is invalid
        mock_get.return_value = mock_agent

        self.controller.activate(self.test_agent_id, self.test_auth_tag)

        # Verify auth tag was verified
        mock_agent.verify_ak_response.assert_called_once_with(self.test_auth_tag)

        # Verify agent was deleted (due to failed activation)
        mock_agent.delete.assert_called_once()

        # Verify agent was NOT saved
        mock_agent.commit_changes.assert_not_called()

        # Verify 400 response with detailed error message
        self.controller.respond.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.respond.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[0][0], 400)
        self.assertIn(self.test_auth_tag, call_args[0][1])
        self.assertIn(self.test_agent_id, call_args[0][1])
        self.assertIn("deleted", call_args[0][1])


if __name__ == "__main__":
    unittest.main()
