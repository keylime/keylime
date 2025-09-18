"""Unit tests for AuthSession helper methods."""

import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch

from keylime.models.base.types import Timestamp
from keylime.models.verifier.auth_session import AuthSession
from keylime.shared_data import cleanup_global_shared_memory, get_shared_memory


class TestAuthSessionHelpers(unittest.TestCase):
    """Test cases for AuthSession helper methods."""

    def setUp(self):
        """Set up test fixtures."""
        # Clean up any existing shared memory
        cleanup_global_shared_memory()
        self.shared_memory = get_shared_memory()
        self.sessions_cache = self.shared_memory.get_or_create_dict("auth_sessions")
        self.test_agent_id = "test-agent-123"

    def tearDown(self):
        """Clean up after tests."""
        cleanup_global_shared_memory()

    def test_delete_stale_from_memory_removes_expired_nonce(self):
        """Test that delete_stale_from_memory removes sessions with expired nonces."""
        now = Timestamp.now()
        past_time = now - timedelta(seconds=10)

        # Create a session with expired nonce
        self.sessions_cache[1] = {  # type: ignore[index]
            "session_id": 1,
            "agent_id": self.test_agent_id,
            "nonce_expires_at": past_time,
            "token_expires_at": None,
        }

        # Call delete_stale_from_memory
        AuthSession.delete_stale_from_memory(self.test_agent_id)

        # Session should be removed
        self.assertNotIn(1, self.sessions_cache)

    def test_delete_stale_from_memory_removes_expired_token(self):
        """Test that delete_stale_from_memory removes sessions with expired tokens."""
        now = Timestamp.now()
        past_time = now - timedelta(seconds=10)

        # Create a session with expired token
        self.sessions_cache[2] = {  # type: ignore[index]
            "session_id": 2,
            "agent_id": self.test_agent_id,
            "nonce_expires_at": None,
            "token_expires_at": past_time,
        }

        # Call delete_stale_from_memory
        AuthSession.delete_stale_from_memory(self.test_agent_id)

        # Session should be removed
        self.assertNotIn(2, self.sessions_cache)

    def test_delete_stale_from_memory_keeps_valid_sessions(self):
        """Test that delete_stale_from_memory keeps valid sessions."""
        now = Timestamp.now()
        future_time = now + timedelta(seconds=60)

        # Create a valid session
        self.sessions_cache[3] = {  # type: ignore[index]
            "session_id": 3,
            "agent_id": self.test_agent_id,
            "nonce_expires_at": future_time,
            "token_expires_at": future_time,
        }

        # Call delete_stale_from_memory
        AuthSession.delete_stale_from_memory(self.test_agent_id)

        # Session should still be present
        self.assertIn(3, self.sessions_cache)

    def test_delete_stale_from_memory_only_affects_target_agent(self):
        """Test that delete_stale_from_memory only affects the specified agent."""
        now = Timestamp.now()
        past_time = now - timedelta(seconds=10)

        # Create sessions for different agents
        self.sessions_cache[4] = {  # type: ignore[index]
            "session_id": 4,
            "agent_id": self.test_agent_id,
            "nonce_expires_at": past_time,
        }
        self.sessions_cache[5] = {  # type: ignore[index]
            "session_id": 5,
            "agent_id": "other-agent-456",
            "nonce_expires_at": past_time,
        }

        # Call delete_stale_from_memory for test_agent_id
        AuthSession.delete_stale_from_memory(self.test_agent_id)

        # Only test_agent_id session should be removed
        self.assertNotIn(4, self.sessions_cache)
        self.assertIn(5, self.sessions_cache)

    def test_get_active_session_for_agent_from_memory(self):
        """Test that get_active_session_for_agent retrieves from shared memory."""
        now = Timestamp.now()
        future_time = now + timedelta(seconds=60)

        # Create an active session in shared memory
        session_data = {
            "session_id": 6,
            "agent_id": self.test_agent_id,
            "active": True,
            "token": "test-token-123",
            "token_expires_at": future_time,
        }
        self.sessions_cache[6] = session_data  # type: ignore[index]

        # Retrieve the session
        result = AuthSession.get_active_session_for_agent(self.test_agent_id)

        # Should return the session data
        self.assertIsNotNone(result)
        self.assertEqual(result["agent_id"], self.test_agent_id)  # type: ignore[index]
        self.assertEqual(result["token"], "test-token-123")  # type: ignore[index]

    @patch("keylime.models.verifier.auth_session.AuthSession.all")
    def test_get_active_session_for_agent_ignores_inactive(self, mock_all):
        """Test that get_active_session_for_agent ignores inactive sessions."""
        now = Timestamp.now()
        future_time = now + timedelta(seconds=60)

        # Mock empty database result
        mock_all.return_value = []

        # Create an inactive session
        self.sessions_cache[7] = {  # type: ignore[index]
            "session_id": 7,
            "agent_id": self.test_agent_id,
            "active": False,
            "token_expires_at": future_time,
        }

        # Retrieve the session
        result = AuthSession.get_active_session_for_agent(self.test_agent_id)

        # Should return None
        self.assertIsNone(result)

    @patch("keylime.models.verifier.auth_session.AuthSession.all")
    def test_get_active_session_for_agent_ignores_expired(self, mock_all):
        """Test that get_active_session_for_agent ignores expired sessions."""
        now = Timestamp.now()
        past_time = now - timedelta(seconds=10)

        # Mock empty database result
        mock_all.return_value = []

        # Create an expired session
        self.sessions_cache[8] = {  # type: ignore[index]
            "session_id": 8,
            "agent_id": self.test_agent_id,
            "active": True,
            "token_expires_at": past_time,
        }

        # Retrieve the session
        result = AuthSession.get_active_session_for_agent(self.test_agent_id)

        # Should return None
        self.assertIsNone(result)

    @patch("keylime.models.verifier.auth_session.AuthSession.all")
    def test_get_active_session_for_agent_from_database(self, mock_all):
        """Test that get_active_session_for_agent falls back to database."""
        now = Timestamp.now()
        future_time = now + timedelta(seconds=60)

        # Mock database session
        mock_session = MagicMock()
        mock_session.token = "db-token-456"
        mock_session.agent_id = self.test_agent_id
        mock_session.active = True
        mock_session.token_expires_at = future_time

        mock_all.return_value = [mock_session]

        # Retrieve the session (not in shared memory, should check DB)
        result = AuthSession.get_active_session_for_agent(self.test_agent_id)

        # Should return session data from database
        self.assertIsNotNone(result)
        self.assertEqual(result["agent_id"], self.test_agent_id)  # type: ignore[index]
        self.assertEqual(result["token"], "db-token-456")  # type: ignore[index]

        # Should also populate shared memory cache
        session_id = hash("db-token-456")
        self.assertIn(session_id, self.sessions_cache)

    def test_delete_active_session_for_agent(self):
        """Test that delete_active_session_for_agent removes the session."""
        # Create an active session
        self.sessions_cache[9] = {  # type: ignore[index]
            "session_id": 9,
            "agent_id": self.test_agent_id,
            "active": True,
        }

        # Delete the session
        AuthSession.delete_active_session_for_agent(self.test_agent_id)

        # Session should be removed
        self.assertNotIn(9, self.sessions_cache)

    def test_delete_active_session_for_agent_only_active(self):
        """Test that delete_active_session_for_agent only deletes active sessions."""
        # Create inactive and active sessions
        self.sessions_cache[10] = {  # type: ignore[index]
            "session_id": 10,
            "agent_id": self.test_agent_id,
            "active": False,
        }
        self.sessions_cache[11] = {  # type: ignore[index]
            "session_id": 11,
            "agent_id": self.test_agent_id,
            "active": True,
        }

        # Delete active session
        AuthSession.delete_active_session_for_agent(self.test_agent_id)

        # Only active session should be removed
        self.assertIn(10, self.sessions_cache)
        self.assertNotIn(11, self.sessions_cache)

    def test_delete_active_session_for_agent_only_target_agent(self):
        """Test that delete_active_session_for_agent only affects target agent."""
        # Create sessions for different agents
        self.sessions_cache[12] = {  # type: ignore[index]
            "session_id": 12,
            "agent_id": self.test_agent_id,
            "active": True,
        }
        self.sessions_cache[13] = {  # type: ignore[index]
            "session_id": 13,
            "agent_id": "other-agent-789",
            "active": True,
        }

        # Delete session for test_agent_id
        AuthSession.delete_active_session_for_agent(self.test_agent_id)

        # Only test_agent_id session should be removed
        self.assertNotIn(12, self.sessions_cache)
        self.assertIn(13, self.sessions_cache)


if __name__ == "__main__":
    unittest.main()
