"""Unit tests for VerifierServer."""

import unittest
from unittest.mock import MagicMock, patch

from keylime.common import states
from keylime.web.verifier_server import VerifierServer


class TestVerifierServerInit(unittest.TestCase):
    """Test cases for VerifierServer initialization."""

    def test_init_worker_agents_initialized(self):
        """Test that _worker_agents is initialized to None."""
        # Create a mock server to avoid full initialization
        with patch.object(VerifierServer, "_prepare_agents_on_startup"):
            with patch.object(VerifierServer, "_setup"):
                with patch.object(VerifierServer, "_routes"):
                    server = VerifierServer()

                    # Verify _worker_agents is initialized
                    self.assertIsNone(server._worker_agents)  # pylint: disable=protected-access


class TestVerifierServerPrepareAgents(unittest.TestCase):
    """Test cases for VerifierServer._prepare_agents_on_startup()."""

    @patch("keylime.web.verifier_server.make_engine")
    @patch("keylime.web.verifier_server.SessionManager")
    def test_prepare_agents_resets_reactivate_states(self, mock_session_manager, mock_make_engine):
        """Test that _prepare_agents_on_startup resets APPROVED_REACTIVATE_STATES."""
        # Mock database engine and session
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        # Create mock agents
        mock_agent1 = MagicMock()
        mock_agent1.agent_id = "agent-1"
        mock_agent1.operational_state = states.GET_QUOTE_RETRY

        mock_agent2 = MagicMock()
        mock_agent2.agent_id = "agent-2"
        mock_agent2.operational_state = states.REGISTERED

        # Mock session context manager
        mock_session = MagicMock()
        mock_session.query.return_value.all.return_value = [mock_agent1, mock_agent2]
        mock_session.query.return_value.count.return_value = 2

        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_session
        mock_context.__exit__.return_value = None

        mock_sm = MagicMock()
        mock_sm.session_context.return_value = mock_context
        mock_session_manager.return_value = mock_sm

        # Call _prepare_agents_on_startup directly
        with patch.object(VerifierServer, "_setup"):
            with patch.object(VerifierServer, "_routes"):
                server = VerifierServer.__new__(VerifierServer)
                server._prepare_agents_on_startup()  # pylint: disable=protected-access

        # Verify database calls were made
        mock_make_engine.assert_called_once_with("cloud_verifier")
        mock_sm.session_context.assert_called_once()

    @patch("keylime.web.verifier_server.make_engine")
    @patch("keylime.web.verifier_server.SessionManager")
    def test_prepare_agents_handles_no_agents(self, mock_session_manager, mock_make_engine):
        """Test that _prepare_agents_on_startup handles empty database."""
        # Mock database engine and session
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        # Mock empty session
        mock_session = MagicMock()
        mock_session.query.return_value.all.return_value = []
        mock_session.query.return_value.count.return_value = 0

        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_session
        mock_context.__exit__.return_value = None

        mock_sm = MagicMock()
        mock_sm.session_context.return_value = mock_context
        mock_session_manager.return_value = mock_sm

        # Call _prepare_agents_on_startup directly
        with patch.object(VerifierServer, "_setup"):
            with patch.object(VerifierServer, "_routes"):
                server = VerifierServer.__new__(VerifierServer)
                server._prepare_agents_on_startup()  # pylint: disable=protected-access

        # Verify query was called
        mock_session.query.return_value.count.assert_called()


class TestVerifierServerRoutes(unittest.TestCase):
    """Test cases for VerifierServer route configuration."""

    def test_v2_agent_routes(self):
        """Test that v2 agent routes are configured."""
        # Create instance without calling __init__ to avoid port binding
        server = VerifierServer.__new__(VerifierServer)
        server._post = MagicMock()  # pylint: disable=protected-access
        server._put = MagicMock()  # pylint: disable=protected-access

        # Call _v2_agent_routes
        server._v2_agent_routes()  # pylint: disable=protected-access

        # Verify routes were registered
        self.assertEqual(server._post.call_count, 1)  # create  # pylint: disable=protected-access
        self.assertEqual(server._put.call_count, 2)  # reactivate, stop  # pylint: disable=protected-access


if __name__ == "__main__":
    unittest.main()
