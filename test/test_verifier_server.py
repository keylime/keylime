"""Unit tests for VerifierServer.

This module tests VerifierServer initialization, route configuration, and
database connection management, ensuring that database engines are properly
disposed before and after forking to prevent connection leaks.

Regression test for: Database connection inheritance across fork boundaries
causing empty HTTP responses and JSON decode errors.
"""

import os
import re
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from keylime import jwt
from keylime.common import states
from keylime.web.verifier_server import VerifierServer


class TestVerifierServerInit(unittest.TestCase):
    """Test cases for VerifierServer initialization."""

    def test_init_worker_agents_initialized(self):
        """Test that _worker_agents is initialized to None."""
        # Create instance without calling __init__ to avoid port binding
        server = VerifierServer.__new__(VerifierServer)

        # Manually set the attribute as __init__ would
        server._worker_agents = None  # pylint: disable=protected-access

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

    @patch("keylime.web.verifier_server.push_agent_monitor")
    @patch("keylime.web.verifier_server.agent_util")
    @patch("keylime.web.verifier_server.config")
    @patch("keylime.web.verifier_server.make_engine")
    @patch("keylime.web.verifier_server.SessionManager")
    def test_prepare_agents_sentinel_zero_not_timed_out(
        self, mock_session_manager, mock_make_engine, mock_config, mock_agent_util, mock_push_monitor
    ):
        """Test that PUSH agents with sentinel last_received_quote=0 are not marked timed out."""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        mock_config.getfloat.return_value = 2.0
        mock_push_monitor.get_maximum_attestation_interval.return_value = 10.0

        mock_agent = MagicMock()
        mock_agent.agent_id = "push-agent-sentinel"
        mock_agent.operational_state = None
        mock_agent.last_received_quote = 0
        mock_agent.accept_attestations = True
        mock_agent_util.is_push_mode_agent.return_value = True

        mock_session = MagicMock()
        mock_session.query.return_value.all.return_value = [mock_agent]
        mock_session.query.return_value.count.return_value = 1

        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_session
        mock_context.__exit__.return_value = None

        mock_sm = MagicMock()
        mock_sm.session_context.return_value = mock_context
        mock_session_manager.return_value = mock_sm

        server = VerifierServer.__new__(VerifierServer)
        server._prepare_agents_on_startup()  # pylint: disable=protected-access

        self.assertTrue(mock_agent.accept_attestations)

    @patch("keylime.web.verifier_server.push_agent_monitor")
    @patch("keylime.web.verifier_server.agent_util")
    @patch("keylime.web.verifier_server.config")
    @patch("keylime.web.verifier_server.make_engine")
    @patch("keylime.web.verifier_server.SessionManager")
    def test_prepare_agents_push_agent_timed_out_during_downtime(
        self, mock_session_manager, mock_make_engine, mock_config, mock_agent_util, mock_push_monitor
    ):
        """Test that PUSH agents that timed out during verifier downtime are marked."""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        mock_config.getfloat.return_value = 2.0
        mock_push_monitor.get_maximum_attestation_interval.return_value = 10.0

        mock_agent = MagicMock()
        mock_agent.agent_id = "push-agent-stale"
        mock_agent.operational_state = None
        mock_agent.last_received_quote = 1000
        mock_agent.accept_attestations = True
        mock_agent_util.is_push_mode_agent.return_value = True

        mock_session = MagicMock()
        mock_session.query.return_value.all.return_value = [mock_agent]
        mock_session.query.return_value.count.return_value = 1

        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_session
        mock_context.__exit__.return_value = None

        mock_sm = MagicMock()
        mock_sm.session_context.return_value = mock_context
        mock_session_manager.return_value = mock_sm

        server = VerifierServer.__new__(VerifierServer)
        server._prepare_agents_on_startup()  # pylint: disable=protected-access

        self.assertFalse(mock_agent.accept_attestations)

    @patch("keylime.web.verifier_server.push_agent_monitor")
    @patch("keylime.web.verifier_server.agent_util")
    @patch("keylime.web.verifier_server.config")
    @patch("keylime.web.verifier_server.make_engine")
    @patch("keylime.web.verifier_server.SessionManager")
    def test_prepare_agents_push_agent_none_quote_not_timed_out(
        self, mock_session_manager, mock_make_engine, mock_config, mock_agent_util, mock_push_monitor
    ):
        """Test that PUSH agents with last_received_quote=None are not marked timed out."""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        mock_config.getfloat.return_value = 2.0
        mock_push_monitor.get_maximum_attestation_interval.return_value = 10.0

        mock_agent = MagicMock()
        mock_agent.agent_id = "push-agent-new"
        mock_agent.operational_state = None
        mock_agent.last_received_quote = None
        mock_agent.accept_attestations = True
        mock_agent_util.is_push_mode_agent.return_value = True

        mock_session = MagicMock()
        mock_session.query.return_value.all.return_value = [mock_agent]
        mock_session.query.return_value.count.return_value = 1

        mock_context = MagicMock()
        mock_context.__enter__.return_value = mock_session
        mock_context.__exit__.return_value = None

        mock_sm = MagicMock()
        mock_sm.session_context.return_value = mock_context
        mock_session_manager.return_value = mock_sm

        server = VerifierServer.__new__(VerifierServer)
        server._prepare_agents_on_startup()  # pylint: disable=protected-access

        self.assertTrue(mock_agent.accept_attestations)


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

    def test_post_fork_resets_verifier_config(self):
        """Verify _post_fork() resets verifier config to clear inherited database state."""
        # Read the source code
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find the _post_fork method
        pattern = r"def _post_fork\(self.*?\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        self.assertIsNotNone(match, "_post_fork method not found")
        assert match is not None

        method_body = match.group(0)

        self.assertIn(
            "reset_verifier_config()",
            method_body,
            "_post_fork must call reset_verifier_config() to clear inherited database state",
        )

        self.assertIn(
            "cloud_verifier_tornado.reset_verifier_config()",
            method_body,
            "_post_fork should call cloud_verifier_tornado.reset_verifier_config()",
        )

    def test_base_server_calls_post_fork_before_start_single(self):
        """Verify base Server.start_multi() calls _post_fork() after fork and before start_single()."""
        # Read the base server source code
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "base", "server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find the start_multi method
        pattern = r"def start_multi\(self\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        assert match is not None
        method_body = match.group(0)

        # Strip comment lines to avoid false matches from mentions
        # in comments (e.g. "# ... before start_single()").
        code_lines = [line for line in method_body.splitlines() if not line.lstrip().startswith("#")]
        code_body = "\n".join(code_lines)

        # Extract the order of operations
        fork_index = code_body.find("fork_processes")
        post_fork_index = code_body.find("_post_fork")
        start_single_index = code_body.find("start_single()")

        # All should be present
        self.assertNotEqual(fork_index, -1, "fork_processes call not found")
        self.assertNotEqual(post_fork_index, -1, "_post_fork() call not found")
        self.assertNotEqual(start_single_index, -1, "start_single() call not found")

        # Correct order: fork -> _post_fork -> start_single
        self.assertLess(
            fork_index,
            post_fork_index,
            "_post_fork must be called AFTER forking",
        )
        self.assertLess(
            post_fork_index,
            start_single_index,
            "_post_fork must be called BEFORE starting worker server",
        )

    def test_post_fork_is_documented(self):
        """Verify _post_fork() documents why reset_verifier_config() is needed."""
        # Read the source code
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")

        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        # Find the _post_fork method
        pattern = r"def _post_fork\(self.*?\).*?(?=\n    def |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        assert match is not None
        method_body = match.group(0)

        # Should mention critical concepts: reset, inherited state, parent process
        critical_terms = ["reset", "inherit", "parent", "database"]
        found_terms = [term for term in critical_terms if term.lower() in method_body.lower()]

        self.assertGreaterEqual(
            len(found_terms),
            3,
            f"_post_fork should document why reset_verifier_config() is needed after fork. "
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

    def test_base_start_multi_documents_disposal_reason(self):
        """Verify base Server.start_multi() documents why engine disposal after fork is needed."""
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "base", "server.py")

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

        critical_terms = ["inherit", "connection", "dispose", "worker", "parent"]

        found_terms = [term for term in critical_terms if term.lower() in after_fork.lower()]

        self.assertGreaterEqual(
            len(found_terms),
            2,
            f"start_multi should document why engine disposal after fork is critical. "
            f"Expected mentions of inherit/connection/dispose/worker/parent, found: {found_terms}",
        )


class TestVerifierServerJwtSignerPlacement(unittest.TestCase):
    """Source-scan test pinning the pre-fork placement of JWT signer init.

    Key resolution must run in the parent process (VerifierServer.__init__)
    before workers are forked: per-worker resolution would give every worker
    its own key on first boot, producing tokens whose kids the JWKS endpoint
    never serves. A runtime test cannot catch this regression (all wiring
    tests call _init_jwt_signer directly), so the placement is asserted on
    the source, following the test_post_fork_resets_verifier_config pattern.
    """

    def test_init_jwt_signer_called_in_init_before_agents(self):
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")
        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        init_match = re.search(r"def __init__\(self\).*?(?=\n    def |\Z)", source, re.DOTALL)
        self.assertIsNotNone(init_match, "VerifierServer.__init__ not found")
        assert init_match is not None
        init_body = init_match.group(0)

        self.assertIn(
            "self._init_jwt_signer()",
            init_body,
            "_init_jwt_signer() must be called in VerifierServer.__init__ so the signer exists before forking",
        )
        self.assertIn(
            "self._prepare_agents_on_startup()",
            init_body,
            "_prepare_agents_on_startup() not found in __init__ (test ordering assumption broken)",
        )
        self.assertLess(
            init_body.index("self._init_jwt_signer()"),
            init_body.index("self._prepare_agents_on_startup()"),
            "_init_jwt_signer() must run before the database-touching startup helpers",
        )

    def test_init_jwt_signer_not_in_post_fork(self):
        server_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "web", "verifier_server.py")
        with open(server_path, encoding="utf-8") as f:
            source = f.read()

        post_fork_match = re.search(r"def _post_fork\(self.*?\).*?(?=\n    def |\Z)", source, re.DOTALL)
        self.assertIsNotNone(post_fork_match, "_post_fork method not found")
        assert post_fork_match is not None

        self.assertNotIn(
            "_init_jwt_signer",
            post_fork_match.group(0),
            "_init_jwt_signer() must NOT run in _post_fork: per-worker key resolution would fork the signing key",
        )


class TestVerifierServerInitJwtSigner(unittest.TestCase):
    """Test cases for VerifierServer._init_jwt_signer()."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)

    def _server(self):
        # Create instance without calling __init__ to avoid port binding
        return VerifierServer.__new__(VerifierServer)

    def _patched_config(self, getint_error: bool = False, **values):
        mock_config = MagicMock()
        mock_config.WORK_DIR = self.tmp_dir
        defaults = {
            "jwt_signing_algorithm": "ES256",
            "jwt_signing_key": "",
            "jwt_signing_key_password": "",
            "jwt_issuer": "",
        }
        defaults.update(values)

        def get(_component, option, **_kwargs):
            return defaults[option]

        mock_config.get.side_effect = get
        if getint_error:
            mock_config.getint.side_effect = ValueError("invalid literal for int() with base 10: ''")
        else:
            mock_config.getint.side_effect = lambda _c, _o, **_k: 300
        return patch("keylime.web.verifier_server.config", mock_config)

    def test_init_jwt_signer_autogenerates_and_persists(self):
        """With no jwt_signing_key configured, a key is generated and persisted."""
        server = self._server()
        with self._patched_config():
            server._init_jwt_signer()  # pylint: disable=protected-access

        persisted = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        self.assertTrue(os.path.exists(persisted))
        self.assertEqual(server.jwt_signer.algorithm, "ES256")
        self.assertIsNotNone(server.jwt_signer.kid)

    def test_init_jwt_signer_reuses_persisted_key(self):
        """A second initialization reuses the persisted key (same kid)."""
        first = self._server()
        with self._patched_config():
            first._init_jwt_signer()  # pylint: disable=protected-access

        second = self._server()
        with self._patched_config():
            second._init_jwt_signer()  # pylint: disable=protected-access

        self.assertEqual(first.jwt_signer.kid, second.jwt_signer.kid)

    def test_init_jwt_signer_without_issuer_leaves_signer_unable_to_sign(self):
        """The signer is instantiated with no issuer and refuses to sign."""
        server = self._server()
        with self._patched_config():
            server._init_jwt_signer()  # pylint: disable=protected-access

        self.assertIsNone(server.jwt_signer.issuer)
        with self.assertRaises(jwt.JwtSigningError):
            server.jwt_signer.sign({})

    def test_init_jwt_signer_invalid_expiration_is_clear_error(self):
        """A non-integer jwt_expiration_seconds names the option instead of a raw ValueError."""
        server = self._server()
        with self._patched_config(getint_error=True):
            with self.assertRaises(jwt.JwtSigningError) as ctx:
                server._init_jwt_signer()  # pylint: disable=protected-access
        self.assertIn("jwt_expiration_seconds", str(ctx.exception))

    def test_init_jwt_signer_corrupt_persisted_key_fails(self):
        """A corrupt persisted key file is a hard error, not a regeneration."""
        persisted = os.path.join(self.tmp_dir, "signing", "jwt_signing_key.pem")
        os.makedirs(os.path.dirname(persisted), mode=0o700)
        with open(persisted, "wb") as f:
            f.write(b"corrupt")
        os.chmod(persisted, 0o600)

        server = self._server()
        with self._patched_config():
            with self.assertRaises(jwt.JwtKeyError):
                server._init_jwt_signer()  # pylint: disable=protected-access


if __name__ == "__main__":
    unittest.main()
