"""Unit tests for SessionController."""

# type: ignore - Controller methods are dynamically bound

import base64
import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch

from keylime.models.base.types import Timestamp
from keylime.shared_data import cleanup_global_shared_memory, get_shared_memory
from keylime.web.verifier.session_controller import SessionController


class TestSessionControllerCreateSession(unittest.TestCase):
    """Test cases for SessionController.create_session()."""

    def setUp(self):
        """Set up test fixtures."""
        cleanup_global_shared_memory()
        # Create mock action_handler
        mock_action_handler = MagicMock()
        mock_action_handler.request = MagicMock()
        mock_action_handler.request.remote_ip = "192.168.1.100"
        self.controller = SessionController(mock_action_handler)
        self.controller.send_response = MagicMock()
        self.test_agent_id = "test-agent-123"

    def tearDown(self):
        """Clean up after tests."""
        cleanup_global_shared_memory()

    @patch("keylime.models.verifier.rate_limiter.RateLimiter")
    @patch("keylime.models.verifier.auth_session.AuthSession.create_in_memory")
    def test_create_session_success(self, mock_create_in_memory, mock_rate_limiter):
        """Test successful session creation."""
        # Mock rate limiter to allow request
        mock_rate_limiter.check_rate_limit.return_value = (True, 0)

        # Mock session creation
        mock_session_data = {
            "session_id": "test-session-id",
            "token": "test-token",
            "agent_id": self.test_agent_id,
            "nonce": b"test-nonce",
            "response": {
                "data": {
                    "type": "session",
                    "id": "test-session-id",
                    "attributes": {"agent_id": self.test_agent_id},
                }
            },
        }
        mock_create_in_memory.return_value = mock_session_data

        # Call create_session
        params = {"data": {"attributes": {"agent_id": self.test_agent_id}}}
        self.controller.create_session(**params)

        # Verify response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 200)
        self.assertEqual(call_args[1]["body"], mock_session_data["response"])

    @patch("keylime.models.verifier.rate_limiter.RateLimiter")
    def test_create_session_missing_agent_id(self, mock_rate_limiter):
        """Test session creation with missing agent_id."""
        # Mock rate limiter to allow request
        mock_rate_limiter.check_rate_limit.return_value = (True, 0)

        # Call with missing agent_id
        params = {"data": {"attributes": {}}}
        self.controller.create_session(**params)

        # Verify 400 response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 400)
        self.assertIn("agent_id is required", str(call_args[1]["body"]))

    @patch("keylime.models.verifier.rate_limiter.RateLimiter")
    def test_create_session_ip_rate_limit(self, mock_rate_limiter):
        """Test session creation blocked by IP rate limit."""
        # Mock rate limiter to block request
        mock_rate_limiter.check_rate_limit.return_value = (False, 30)

        # Call create_session
        params = {"data": {"attributes": {"agent_id": self.test_agent_id}}}
        self.controller.create_session(**params)

        # Verify 429 response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 429)
        self.assertIn("Rate limit exceeded", str(call_args[1]["body"]))

        # Verify Retry-After header was set
        self.controller._action_handler.set_header.assert_called_with(  # pylint: disable=protected-access
            "Retry-After", "30"
        )

    @patch("keylime.models.verifier.rate_limiter.RateLimiter")
    def test_create_session_agent_rate_limit(self, mock_rate_limiter):
        """Test session creation blocked by agent rate limit."""
        # Mock rate limiter - allow IP, block agent
        mock_rate_limiter.check_rate_limit.side_effect = [(True, 0), (False, 60)]

        # Call create_session
        params = {"data": {"attributes": {"agent_id": self.test_agent_id}}}
        self.controller.create_session(**params)

        # Verify 429 response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 429)
        self.assertIn("Rate limit exceeded for this agent", str(call_args[1]["body"]))

    @patch("keylime.models.verifier.rate_limiter.RateLimiter")
    @patch("keylime.models.verifier.auth_session.AuthSession.create_in_memory")
    def test_create_session_validation_error(self, mock_create_in_memory, mock_rate_limiter):
        """Test session creation with validation errors."""
        # Mock rate limiter to allow request
        mock_rate_limiter.check_rate_limit.return_value = (True, 0)

        # Mock session creation to return errors
        mock_create_in_memory.return_value = {
            "errors": {
                "authentication_supported": ["must include tpm_pop authentication type"],
                "nonce": ["is required"],
            }
        }

        # Call create_session
        params = {"data": {"attributes": {"agent_id": self.test_agent_id}}}
        self.controller.create_session(**params)

        # Verify 400 response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 400)

    @patch("keylime.models.verifier.rate_limiter.RateLimiter")
    @patch("keylime.models.verifier.auth_session.AuthSession.create_in_memory")
    @patch("keylime.models.verifier.auth_session.AuthSession.delete_stale_from_memory")
    def test_create_session_cleans_stale(self, mock_delete_stale, mock_create_in_memory, mock_rate_limiter):
        """Test that create_session cleans up stale sessions."""
        # Mock rate limiter to allow request
        mock_rate_limiter.check_rate_limit.return_value = (True, 0)

        # Mock session creation
        mock_session_data = {
            "session_id": "test-session-id",
            "response": {"data": {"type": "session"}},
        }
        mock_create_in_memory.return_value = mock_session_data

        # Call create_session
        params = {"data": {"attributes": {"agent_id": self.test_agent_id}}}
        self.controller.create_session(**params)

        # Verify stale sessions were cleaned up
        mock_delete_stale.assert_called_once_with(self.test_agent_id)


class TestSessionControllerUpdateSession(unittest.TestCase):
    """Test cases for SessionController.update_session()."""

    def setUp(self):
        """Set up test fixtures."""
        cleanup_global_shared_memory()
        self.shared_memory = get_shared_memory()
        self.sessions_cache = self.shared_memory.get_or_create_dict("auth_sessions")
        # Create mock action_handler
        mock_action_handler = MagicMock()
        self.controller = SessionController(mock_action_handler)
        self.controller.send_response = MagicMock()
        self.test_agent_id = "test-agent-123"
        self.test_session_id = "test-session-id"

    def tearDown(self):
        """Clean up after tests."""
        cleanup_global_shared_memory()

    def test_update_session_missing_agent_id(self):
        """Test update_session with missing agent_id."""
        # Call with missing agent_id
        params = {"data": {"attributes": {}}}
        self.controller.update_session(self.test_session_id, **params)

        # Verify 400 response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 400)
        self.assertIn("agent_id is required", str(call_args[1]["body"]))

    def test_update_session_not_found(self):
        """Test update_session with non-existent session."""
        # Call with session that doesn't exist
        params = {"data": {"attributes": {"agent_id": self.test_agent_id}}}
        self.controller.update_session(self.test_session_id, **params)

        # Verify 404 response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 404)
        self.assertIn("Session not found", str(call_args[1]["body"]))

    def test_update_session_agent_id_mismatch(self):
        """Test update_session with agent_id mismatch."""
        # Create session in cache with different agent_id
        now = Timestamp.now()
        self.sessions_cache[self.test_session_id] = {  # type: ignore[index]
            "session_id": self.test_session_id,
            "agent_id": "different-agent",
            "nonce": b"test-nonce",
            "nonce_created_at": now,
            "nonce_expires_at": now + timedelta(seconds=60),
        }

        # Call with different agent_id
        params = {"data": {"attributes": {"agent_id": self.test_agent_id}}}
        self.controller.update_session(self.test_session_id, **params)

        # Verify 400 response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 400)
        self.assertIn("Agent ID mismatch", str(call_args[1]["body"]))

    def test_update_session_nonce_expired(self):
        """Test update_session with expired nonce."""
        # Create session in cache with expired nonce
        now = Timestamp.now()
        past_time = now - timedelta(seconds=10)
        nonce = b"test-nonce"

        self.sessions_cache[self.test_session_id] = {  # type: ignore[index]
            "session_id": self.test_session_id,
            "agent_id": self.test_agent_id,
            "nonce": nonce,
            "nonce_created_at": past_time - timedelta(seconds=60),
            "nonce_expires_at": past_time,
        }

        # Call with proof data
        params = {
            "data": {
                "attributes": {
                    "agent_id": self.test_agent_id,
                    "authentication_provided": [
                        {
                            "authentication_type": "tpm_pop",
                            "data": {
                                "message": base64.b64encode(b"message").decode("utf-8"),
                                "signature": base64.b64encode(b"signature").decode("utf-8"),
                            },
                        }
                    ],
                }
            }
        }
        self.controller.update_session(self.test_session_id, **params)

        # Verify 200 response with evaluation:fail
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 200)
        body = call_args[1]["body"]
        self.assertEqual(body["data"]["attributes"]["evaluation"], "fail")

        # Verify session was deleted from cache
        self.assertNotIn(self.test_session_id, self.sessions_cache)

    @patch("keylime.web.verifier.session_controller.get_session")
    def test_update_session_agent_not_enrolled(self, mock_get_session):
        """Test update_session with unenrolled agent."""
        # Create session in cache
        now = Timestamp.now()
        nonce = b"test-nonce"

        self.sessions_cache[self.test_session_id] = {  # type: ignore[index]
            "session_id": self.test_session_id,
            "agent_id": self.test_agent_id,
            "nonce": nonce,
            "nonce_created_at": now,
            "nonce_expires_at": now + timedelta(seconds=60),
        }

        # Mock database query to return no agent
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.one_or_none.return_value = None
        mock_get_session.return_value = mock_session

        # Call update_session
        params = {
            "data": {
                "attributes": {
                    "agent_id": self.test_agent_id,
                    "authentication_provided": [
                        {
                            "authentication_type": "tpm_pop",
                            "data": {
                                "message": base64.b64encode(b"message").decode("utf-8"),
                                "signature": base64.b64encode(b"signature").decode("utf-8"),
                            },
                        }
                    ],
                }
            }
        }
        self.controller.update_session(self.test_session_id, **params)

        # Verify 200 response with evaluation:fail
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 200)
        body = call_args[1]["body"]
        self.assertEqual(body["data"]["attributes"]["evaluation"], "fail")

    @patch("keylime.web.verifier.session_controller.get_session")
    @patch("keylime.models.verifier.auth_session.AuthSession.create_from_memory")
    def test_update_session_authentication_failed(self, mock_create_from_memory, mock_get_session):
        """Test update_session with failed authentication."""
        # Create session in cache
        now = Timestamp.now()
        nonce = b"test-nonce"

        self.sessions_cache[self.test_session_id] = {  # type: ignore[index]
            "session_id": self.test_session_id,
            "agent_id": self.test_agent_id,
            "nonce": nonce,
            "nonce_created_at": now,
            "nonce_expires_at": now + timedelta(seconds=60),
        }

        # Mock database query to return an agent
        mock_agent = MagicMock()
        mock_agent.agent_id = self.test_agent_id
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.one_or_none.return_value = mock_agent
        mock_get_session.return_value = mock_session

        # Mock AuthSession.create_from_memory to return errors
        mock_auth_session = MagicMock()
        mock_auth_session.errors = {"ak_attest": ["must verify against ak_attest"]}
        mock_auth_session.agent_id = self.test_agent_id
        mock_auth_session.nonce = nonce
        mock_auth_session.nonce_created_at = now
        mock_auth_session.nonce_expires_at = now + timedelta(seconds=60)
        mock_auth_session.ak_attest = b"attest"
        mock_auth_session.ak_sign = b"sign"
        mock_auth_session.pop_received_at = now
        mock_create_from_memory.return_value = mock_auth_session

        # Call update_session
        params = {
            "data": {
                "attributes": {
                    "agent_id": self.test_agent_id,
                    "authentication_provided": [
                        {
                            "authentication_type": "tpm_pop",
                            "data": {
                                "message": base64.b64encode(b"message").decode("utf-8"),
                                "signature": base64.b64encode(b"signature").decode("utf-8"),
                            },
                        }
                    ],
                }
            }
        }
        self.controller.update_session(self.test_session_id, **params)

        # Verify 401 response
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 401)

    @patch("keylime.web.verifier.session_controller.get_session")
    @patch("keylime.models.verifier.auth_session.AuthSession.create_from_memory")
    @patch("keylime.web.verifier.session_controller.config")
    def test_update_session_success(self, mock_config, mock_create_from_memory, mock_get_session):
        """Test successful session update."""
        # Create session in cache
        now = Timestamp.now()
        nonce = b"test-nonce"

        self.sessions_cache[self.test_session_id] = {  # type: ignore[index]
            "session_id": self.test_session_id,
            "agent_id": self.test_agent_id,
            "nonce": nonce,
            "nonce_created_at": now,
            "nonce_expires_at": now + timedelta(seconds=60),
        }

        # Mock database query to return an agent
        mock_agent = MagicMock()
        mock_agent.agent_id = self.test_agent_id
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.one_or_none.return_value = mock_agent
        mock_get_session.return_value = mock_session

        # Mock config
        mock_config.getboolean.return_value = False  # Don't keep in memory

        # Mock AuthSession.create_from_memory to return valid session
        mock_auth_session = MagicMock()
        mock_auth_session.errors = {}  # No errors
        mock_auth_session.agent_id = self.test_agent_id
        mock_auth_session.token = "test-token"
        mock_auth_session.nonce = nonce
        mock_auth_session.nonce_created_at = now
        mock_auth_session.nonce_expires_at = now + timedelta(seconds=60)
        mock_auth_session.token_expires_at = now + timedelta(seconds=3600)
        mock_auth_session.ak_attest = b"attest"
        mock_auth_session.ak_sign = b"sign"
        mock_auth_session.pop_received_at = now
        mock_create_from_memory.return_value = mock_auth_session

        # Call update_session
        params = {
            "data": {
                "attributes": {
                    "agent_id": self.test_agent_id,
                    "authentication_provided": [
                        {
                            "authentication_type": "tpm_pop",
                            "data": {
                                "message": base64.b64encode(b"message").decode("utf-8"),
                                "signature": base64.b64encode(b"signature").decode("utf-8"),
                            },
                        }
                    ],
                }
            }
        }
        self.controller.update_session(self.test_session_id, **params)

        # Verify 200 response with evaluation:pass
        self.controller.send_response.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.send_response.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[1]["code"], 200)
        body = call_args[1]["body"]
        self.assertEqual(body["data"]["attributes"]["evaluation"], "pass")
        self.assertIn("token", body["data"]["attributes"])


class TestSessionControllerLegacyEndpoints(unittest.TestCase):
    """Test cases for legacy SessionController endpoints."""

    def setUp(self):
        """Set up test fixtures."""
        cleanup_global_shared_memory()
        # Create mock action_handler
        mock_action_handler = MagicMock()
        self.controller = SessionController(mock_action_handler)
        self.controller.respond = MagicMock()
        self.test_agent_id = "test-agent-123"
        self.test_token = "test-token"

    def tearDown(self):
        """Clean up after tests."""
        cleanup_global_shared_memory()

    @patch("keylime.models.verifier.auth_session.AuthSession.get")
    @patch("keylime.models.verifier.auth_session.AuthSession.delete_stale")
    def test_show_success(self, _mock_delete_stale, mock_get):
        """Test successful show endpoint."""
        # Mock AuthSession.get to return agent
        mock_agent = MagicMock()
        mock_agent.active = True
        mock_agent.render.return_value = {"token": self.test_token}
        mock_get.return_value = mock_agent

        # Call show
        self.controller.show(self.test_agent_id, self.test_token)

        # Verify response
        self.controller.respond.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.respond.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[0][0], 200)

    @patch("keylime.models.verifier.auth_session.AuthSession.get")
    @patch("keylime.models.verifier.auth_session.AuthSession.delete_stale")
    def test_show_not_found(self, _mock_delete_stale, mock_get):
        """Test show endpoint with non-existent agent."""
        # Mock AuthSession.get to return None
        mock_get.return_value = None

        # Call show
        self.controller.show(self.test_agent_id, self.test_token)

        # Verify 404 response
        self.controller.respond.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.respond.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[0][0], 404)

    @patch("keylime.models.verifier.auth_session.AuthSession.get")
    @patch("keylime.models.verifier.auth_session.AuthSession.delete_stale")
    def test_show_not_active(self, _mock_delete_stale, mock_get):
        """Test show endpoint with inactive agent."""
        # Mock AuthSession.get to return inactive agent
        mock_agent = MagicMock()
        mock_agent.active = False
        mock_get.return_value = mock_agent

        # Call show
        self.controller.show(self.test_agent_id, self.test_token)

        # Verify 404 response
        self.controller.respond.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.respond.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[0][0], 404)

    @patch("keylime.models.verifier.auth_session.AuthSession.delete_stale")
    @patch("keylime.web.verifier.session_controller.get_session")
    @patch("keylime.models.verifier.auth_session.AuthSession.create")
    def test_create_success(self, mock_create, mock_get_session, _mock_delete_stale):
        """Test successful create endpoint."""
        # Mock database query
        mock_agent = MagicMock()
        mock_agent.agent_id = self.test_agent_id
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.one_or_none.return_value = mock_agent
        mock_get_session.return_value = mock_session

        # Mock AuthSession.create
        mock_auth_session = MagicMock()
        mock_auth_session.errors = {}
        mock_auth_session.render.return_value = {"token": self.test_token}
        mock_auth_session.commit_changes = MagicMock()
        mock_create.return_value = mock_auth_session

        # Call create
        params = {"data": {}}
        self.controller.create(self.test_agent_id, **params)

        # Verify response
        self.controller.respond.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.respond.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[0][0], 200)

    @patch("keylime.web.verifier.session_controller.get_session")
    def test_create_agent_not_found(self, mock_get_session):
        """Test create endpoint with non-existent agent."""
        # Mock database query to return None
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.one_or_none.return_value = None
        mock_get_session.return_value = mock_session

        # Call create
        params = {"data": {}}
        self.controller.create(self.test_agent_id, **params)

        # Verify 404 response
        self.controller.respond.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.respond.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[0][0], 404)

    @patch("keylime.web.verifier.session_controller.get_session")
    @patch("keylime.models.verifier.auth_session.AuthSession.get")
    def test_update_success(self, mock_get, mock_get_session):
        """Test successful update endpoint."""
        # Mock database query
        mock_agent = MagicMock()
        mock_agent.agent_id = self.test_agent_id
        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.one_or_none.return_value = mock_agent
        mock_get_session.return_value = mock_session

        # Mock AuthSession.get
        mock_auth_session = MagicMock()
        mock_auth_session.errors = {}
        mock_auth_session.render.return_value = {"token": self.test_token}
        mock_auth_session.receive_pop = MagicMock()
        mock_auth_session.commit_changes = MagicMock()
        mock_get.return_value = mock_auth_session

        # Call update
        params = {"data": {}}
        self.controller.update(self.test_agent_id, self.test_token, **params)

        # Verify response
        self.controller.respond.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.respond.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[0][0], 200)

    @patch("keylime.web.verifier.session_controller.get_session")
    @patch("keylime.models.verifier.auth_session.AuthSession.get")
    def test_update_not_found(self, mock_get, _mock_get_session):
        """Test update endpoint with non-existent session."""
        # Mock AuthSession.get to return None
        mock_get.return_value = None

        # Call update
        params = {"data": {}}
        self.controller.update(self.test_agent_id, self.test_token, **params)

        # Verify 404 response
        self.controller.respond.assert_called_once()  # type: ignore[attr-defined]
        call_args = self.controller.respond.call_args  # type: ignore[attr-defined]
        self.assertEqual(call_args[0][0], 404)


if __name__ == "__main__":
    unittest.main()
