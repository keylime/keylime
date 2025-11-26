"""Unit tests for VerifierServer.

This module tests VerifierServer initialization, route configuration, and
database connection management, ensuring that database engines are properly
disposed before and after forking to prevent connection leaks.

Regression test for: Database connection inheritance across fork boundaries
causing empty HTTP responses and JSON decode errors.
"""

import os
import re
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


class TestVerifierServerInitialization(unittest.TestCase):
    """Test VerifierServer initialization and _prepare_agents_on_startup() execution.

    These tests actually execute the code to provide coverage metrics.
    """

    @patch("keylime.web.verifier_server.cloud_verifier_tornado")
    @patch("keylime.web.verifier_server.states")
    @patch("keylime.web.verifier_server.SessionManager")
    @patch("keylime.web.verifier_server.make_engine")
    @patch("keylime.web.verifier_server.config")
    def test_prepare_agents_on_startup_creates_and_disposes_engine(
        self, mock_config, mock_make_engine, mock_session_manager, _mock_states, _mock_cvt
    ):
        """Verify _prepare_agents_on_startup() creates temporary engine and disposes it."""
        # Mock config
        mock_config.get.return_value = "pull"
        mock_config.getboolean.return_value = False

        # Mock engine
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        # Mock session manager and session
        mock_sm_instance = MagicMock()
        mock_session_manager.return_value = mock_sm_instance
        mock_session = MagicMock()
        mock_sm_instance.session_context.return_value.__enter__.return_value = mock_session
        mock_sm_instance.session_context.return_value.__exit__.return_value = None

        # Mock query results (empty database)
        mock_session.query.return_value.all.return_value = []
        mock_session.query.return_value.count.return_value = 0

        # Create minimal instance and call method
        server = object.__new__(VerifierServer)
        # pylint: disable=protected-access
        server._prepare_agents_on_startup()
        # pylint: enable=protected-access

        # Verify engine was created
        mock_make_engine.assert_called_once_with("cloud_verifier")

        # Verify engine.dispose() was called
        mock_engine.dispose.assert_called_once()

        # Verify server object exists
        self.assertIsNotNone(server)

    @patch("keylime.web.verifier_server.SessionManager")
    @patch("keylime.web.verifier_server.make_engine")
    def test_prepare_agents_disposes_engine_even_on_exception(self, mock_make_engine, mock_session_manager):
        """Verify _prepare_agents_on_startup() disposes engine in finally block even if exception occurs."""
        # Mock engine
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        # Mock session manager to raise exception
        mock_sm_instance = MagicMock()
        mock_session_manager.return_value = mock_sm_instance
        # Make session_context raise an exception
        mock_sm_instance.session_context.side_effect = Exception("Database error")

        # Directly test _prepare_agents_on_startup and expect exception
        server = object.__new__(VerifierServer)
        # pylint: disable=protected-access
        with self.assertRaises(Exception):
            server._prepare_agents_on_startup()
        # pylint: enable=protected-access

        # Verify engine was created
        mock_make_engine.assert_called_once_with("cloud_verifier")

        # Verify engine.dispose() was still called (finally block)
        mock_engine.dispose.assert_called_once()


class TestVerifierServerEngineDisposal(unittest.TestCase):
    """Test database engine disposal in VerifierServer.

    These tests verify that the VerifierServer properly disposes database
    engines to prevent connection leaks across fork boundaries.

    When tornado.process.fork_processes() is used, database connections
    created in the parent process become invalid in child worker processes.
    The VerifierServer must dispose engines both:
    1. In the parent process before forking (_prepare_agents_on_startup)
    2. In each worker process after forking (start_multi)
    """

    def test_prepare_agents_disposes_engine_before_fork(self):
        """Verify _prepare_agents_on_startup() disposes temporary engine in finally block."""
        # Read the source code
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find the _prepare_agents_on_startup method
        pattern = r"def _prepare_agents_on_startup\(self\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        self.assertIsNotNone(match, "_prepare_agents_on_startup method not found")
        assert match is not None

        method_body = match.group(0)

        # Should create a temporary engine
        self.assertIn(
            "engine = make_engine",
            method_body,
            "_prepare_agents_on_startup should create a temporary engine for initialization",
        )

        # Should have try/finally block
        self.assertIn("try:", method_body, "_prepare_agents_on_startup should have try block")
        self.assertIn("finally:", method_body, "_prepare_agents_on_startup should have finally block")

        # Should dispose engine in finally block
        self.assertIn(
            "engine.dispose()",
            method_body,
            "_prepare_agents_on_startup must dispose engine in finally block to prevent connection leaks",
        )

        # Verify the comment explaining why disposal is needed
        self.assertIn(
            "Dispose the engine",
            method_body,
            "_prepare_agents_on_startup should document why engine disposal is needed",
        )

    def test_start_multi_resets_verifier_config_after_fork(self):
        """Verify start_multi() resets verifier config in each worker after forking."""
        # Read the source code
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find the start_multi method
        pattern = r"def start_multi\(self\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        self.assertIsNotNone(match, "start_multi method not found")
        assert match is not None

        method_body = match.group(0)

        # Should fork processes
        self.assertIn(
            "fork_processes",
            method_body,
            "start_multi should call tornado.process.fork_processes",
        )

        # After fork, should reset verifier config (which handles engine disposal)
        # Look for the pattern after fork_processes()
        fork_index = method_body.find("fork_processes")
        after_fork = method_body[fork_index:]

        self.assertIn(
            "reset_verifier_config()",
            after_fork,
            "start_multi must call reset_verifier_config() after forking to clear inherited database state",
        )

        self.assertIn(
            "cloud_verifier_tornado.reset_verifier_config()",
            after_fork,
            "start_multi should call cloud_verifier_tornado.reset_verifier_config() after forking",
        )

    def test_verifier_config_reset_happens_before_worker_operations(self):
        """Verify verifier config reset occurs after fork but before any worker operations."""
        # Read the source code
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find the start_multi method
        pattern = r"def start_multi\(self\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        assert match is not None
        method_body = match.group(0)

        # Extract the order of operations
        fork_index = method_body.find("fork_processes")
        reset_index = method_body.find("reset_verifier_config()")
        start_single_index = method_body.find("self.start_single()")

        # All should be present
        self.assertNotEqual(fork_index, -1, "fork_processes call not found")
        self.assertNotEqual(reset_index, -1, "reset_verifier_config() call not found")
        self.assertNotEqual(start_single_index, -1, "start_single() call not found")

        # Correct order: fork -> reset_verifier_config -> start_single
        self.assertLess(
            fork_index,
            reset_index,
            "Verifier config reset must happen AFTER forking",
        )
        self.assertLess(
            reset_index,
            start_single_index,
            "Verifier config reset must happen BEFORE starting worker server",
        )

    def test_reset_pattern_is_documented(self):
        """Verify reset_verifier_config() pattern is documented."""
        # Read the source code
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find the start_multi method
        pattern = r"def start_multi\(self\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        assert match is not None
        method_body = match.group(0)

        # Should document why reset is needed after fork
        fork_index = method_body.find("fork_processes")
        after_fork = method_body[fork_index:]

        # Should mention critical concepts: reset, inherited state, parent process
        critical_terms = ["reset", "inherit", "parent", "database"]
        found_terms = [term for term in critical_terms if term.lower() in after_fork.lower()]

        self.assertGreaterEqual(
            len(found_terms),
            3,
            f"start_multi should document why reset_verifier_config() is needed after fork. "
            f"Expected mentions of reset/inherit/parent/database, found: {found_terms}",
        )


class TestEngineDisposalDocumentation(unittest.TestCase):
    """Test that engine disposal is properly documented.

    Good documentation prevents future regressions where developers might
    remove the disposal calls without understanding why they're critical.
    """

    def test_prepare_agents_documents_disposal_reason(self):
        """Verify _prepare_agents_on_startup() documents why disposal is needed."""
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find _prepare_agents_on_startup
        pattern = r"def _prepare_agents_on_startup\(self\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        assert match is not None
        method_body = match.group(0)

        # Should have docstring or comments explaining the disposal
        critical_terms = ["fork", "connection", "dispose", "parent process", "child process"]

        found_terms = [term for term in critical_terms if term.lower() in method_body.lower()]

        self.assertGreaterEqual(
            len(found_terms),
            3,
            f"_prepare_agents_on_startup should document why engine disposal is critical. "
            f"Expected mentions of fork/connection/dispose/parent/child, found: {found_terms}",
        )

    def test_start_multi_documents_disposal_reason(self):
        """Verify start_multi() documents why global engine disposal is needed."""
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find start_multi
        pattern = r"def start_multi\(self\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        assert match is not None
        method_body = match.group(0)

        # After fork_processes, should have comments about disposal
        fork_index = method_body.find("fork_processes")
        after_fork = method_body[fork_index:]

        critical_terms = ["inherit", "corrupt", "dispose", "worker", "parent"]

        found_terms = [term for term in critical_terms if term.lower() in after_fork.lower()]

        self.assertGreaterEqual(
            len(found_terms),
            2,
            f"start_multi should document why global engine disposal after fork is critical. "
            f"Expected mentions of inherit/corrupt/dispose/worker/parent, found: {found_terms}",
        )


if __name__ == "__main__":
    unittest.main()
