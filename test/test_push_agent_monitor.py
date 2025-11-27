"""Unit tests for push_agent_monitor module.

This module tests the PUSH mode agent timeout detection functionality,
ensuring that agents that stop sending attestations are properly marked
as failed after exceeding the timeout threshold.
"""

import time
import unittest
from unittest.mock import MagicMock, Mock, call, patch

from sqlalchemy import create_engine

from keylime.agent_util import is_push_mode_agent
from keylime.db.keylime_db import SessionManager
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist, VerifierMbpolicy
from keylime.push_agent_monitor import (
    _agent_timeout_handles,
    _mark_agent_failed,
    cancel_agent_timeout,
    check_push_agent_timeouts,
    get_maximum_attestation_interval,
    schedule_agent_timeout,
)


class TestPushAgentMonitor(unittest.TestCase):
    """Test PUSH mode agent timeout detection functionality."""

    def setUp(self):
        """Set up test database with mock agents."""
        # Clear global timeout handles to ensure test isolation
        _agent_timeout_handles.clear()

        self.engine = create_engine("sqlite://")
        VerfierMain.metadata.create_all(self.engine, checkfirst=True)
        self.session = SessionManager().make_session(self.engine)
        self.current_time = int(time.time())

        # Create mock allowlist and mbpolicy (required for VerfierMain foreign keys)
        allowlist = VerifierAllowlist(
            name="test-allowlist",
            tpm_policy='{"mask": "0x408400"}',
            ima_policy='{"allowlist": {}, "exclude": []}',
        )
        mbpolicy = VerifierMbpolicy(
            name="test-mbpolicy",
            mb_policy="[]",
        )
        self.session.add(allowlist)
        self.session.add(mbpolicy)
        self.session.commit()

        # Store for reuse
        self.allowlist = allowlist
        self.mbpolicy = mbpolicy

    def tearDown(self):
        """Clean up test database."""
        self.session.close()
        # Clear global timeout handles after each test
        _agent_timeout_handles.clear()

    def _create_push_agent(
        self, agent_id, accept_attestations=True, last_received_quote=None, operational_state=None, ip=None, port=None
    ):
        """Helper to create a PUSH mode agent with specified attributes.

        Args:
            agent_id: Unique agent identifier
            accept_attestations: Whether agent is accepting attestations
            last_received_quote: Timestamp of last received attestation (None if never received)
            operational_state: Operational state (None for PUSH mode, integer for PULL mode)
            ip: IP address (None for PUSH mode, set for PULL mode)
            port: Port number (None for PUSH mode, set for PULL mode)
        """
        agent = VerfierMain(
            agent_id=agent_id,
            v="test_v_value",
            ip=ip,  # PUSH mode: None, PULL mode: actual IP
            port=port,  # PUSH mode: None, PULL mode: actual port
            operational_state=operational_state,
            accept_attestations=accept_attestations,
            last_received_quote=last_received_quote,
            last_successful_attestation=last_received_quote,
            attestation_count=0 if last_received_quote is None else 1,
            public_key="",
            tpm_policy="{}",
            meta_data="{}",
            ima_sign_verification_keys="",
            revocation_key="",
            accept_tpm_hash_algs=["sha256"],
            accept_tpm_encryption_algs=["rsa"],
            accept_tpm_signing_algs=["rsassa"],
            hash_alg="",
            enc_alg="",
            sign_alg="",
            verifier_id="default",
            verifier_ip="127.0.0.1",
            verifier_port=8881,
            ima_policy=self.allowlist,
            mb_policy=self.mbpolicy,
        )
        self.session.add(agent)
        self.session.commit()
        return agent

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    @patch("keylime.push_agent_monitor.time.time")
    def test_check_push_agent_timeouts_healthy_agent(self, mock_time, mock_session_context, mock_config):
        """Test that healthy agents are not marked as failed."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0  # quote_interval = 2 seconds
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None
        mock_time.return_value = self.current_time

        # Create a healthy PUSH mode agent (received attestation 1 second ago)
        self._create_push_agent(
            agent_id="healthy-agent",
            accept_attestations=True,
            last_received_quote=self.current_time - 1,  # 1 second ago
            operational_state=None,  # PUSH mode
        )

        # Run timeout check
        check_push_agent_timeouts()

        # Verify agent is still accepting attestations
        agent = self.session.query(VerfierMain).filter_by(agent_id="healthy-agent").first()
        self.assertIsNotNone(agent)
        assert agent is not None  # Type narrowing for pyright
        self.assertTrue(agent.accept_attestations)

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    @patch("keylime.push_agent_monitor.time.time")
    def test_check_push_agent_timeouts_timed_out_agent(self, mock_time, mock_session_context, mock_config):
        """Test that timed-out agents are marked as failed."""
        # Configure mocks
        quote_interval = 2.0
        mock_config.getfloat.return_value = quote_interval
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None
        mock_time.return_value = self.current_time

        # Create a timed-out PUSH mode agent (received attestation 10 seconds ago)
        # Timeout threshold is get_maximum_attestation_interval(2.0) = 4.0 seconds
        self._create_push_agent(
            agent_id="timed-out-agent",
            accept_attestations=True,
            last_received_quote=self.current_time - 10,  # 10 seconds ago (> 4 second threshold)
            operational_state=None,  # PUSH mode
        )

        # Run timeout check
        check_push_agent_timeouts()

        # Verify agent is no longer accepting attestations
        agent = self.session.query(VerfierMain).filter_by(agent_id="timed-out-agent").first()
        self.assertIsNotNone(agent)
        assert agent is not None  # Type narrowing for pyright
        self.assertFalse(agent.accept_attestations)

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    @patch("keylime.push_agent_monitor.time.time")
    def test_check_push_agent_timeouts_never_received_attestation(self, mock_time, mock_session_context, mock_config):
        """Test that agents that never received an attestation are not marked as failed."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None
        mock_time.return_value = self.current_time

        # Create a PUSH mode agent that has never received an attestation
        self._create_push_agent(
            agent_id="never-received-agent",
            accept_attestations=True,
            last_received_quote=None,  # Never received an attestation
            operational_state=None,  # PUSH mode
        )

        # Run timeout check
        check_push_agent_timeouts()

        # Verify agent is still accepting attestations (we don't timeout agents that never connected)
        agent = self.session.query(VerfierMain).filter_by(agent_id="never-received-agent").first()
        self.assertIsNotNone(agent)
        assert agent is not None  # Type narrowing for pyright
        self.assertTrue(agent.accept_attestations)

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    @patch("keylime.push_agent_monitor.time.time")
    def test_check_push_agent_timeouts_already_failed_agent(self, mock_time, mock_session_context, mock_config):
        """Test that already-failed agents are not updated again (to prevent log spam)."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None
        mock_time.return_value = self.current_time

        # Create a timed-out PUSH mode agent that's already marked as failed
        self._create_push_agent(
            agent_id="already-failed-agent",
            accept_attestations=False,  # Already failed
            last_received_quote=self.current_time - 10,  # 10 seconds ago
            operational_state=None,  # PUSH mode
        )

        # Run timeout check
        check_push_agent_timeouts()

        # Verify agent is still marked as failed (no change)
        agent = self.session.query(VerfierMain).filter_by(agent_id="already-failed-agent").first()
        self.assertIsNotNone(agent)
        assert agent is not None  # Type narrowing for pyright
        self.assertFalse(agent.accept_attestations)

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    @patch("keylime.push_agent_monitor.time.time")
    def test_check_push_agent_timeouts_pull_mode_agent_ignored(self, mock_time, mock_session_context, mock_config):
        """Test that PULL mode agents are ignored by the timeout check."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None
        mock_time.return_value = self.current_time

        # Create a PULL mode agent (has IP and port set)
        self._create_push_agent(
            agent_id="pull-mode-agent",
            accept_attestations=True,
            last_received_quote=self.current_time - 10,  # 10 seconds ago
            operational_state=7,  # GET_QUOTE state (indicates PULL mode)
            ip="127.0.0.1",  # PULL mode agents have IP
            port=9002,  # PULL mode agents have port
        )

        # Run timeout check
        check_push_agent_timeouts()

        # Verify PULL mode agent is still accepting attestations (not affected by PUSH timeout)
        agent = self.session.query(VerfierMain).filter_by(agent_id="pull-mode-agent").first()
        self.assertIsNotNone(agent)
        assert agent is not None  # Type narrowing for pyright
        self.assertTrue(agent.accept_attestations)

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    @patch("keylime.push_agent_monitor.time.time")
    def test_check_push_agent_timeouts_multiple_agents(self, mock_time, mock_session_context, mock_config):
        """Test timeout detection with multiple agents in different states."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0  # quote_interval = 2 seconds (threshold = 4 seconds)
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None
        mock_time.return_value = self.current_time

        # Create multiple agents with different states
        self._create_push_agent(
            agent_id="healthy-1",
            accept_attestations=True,
            last_received_quote=self.current_time - 1,  # Healthy (1s ago)
            operational_state=None,
        )
        self._create_push_agent(
            agent_id="healthy-2",
            accept_attestations=True,
            last_received_quote=self.current_time - 3,  # Healthy (3s ago, just under threshold)
            operational_state=None,
        )
        self._create_push_agent(
            agent_id="timed-out-1",
            accept_attestations=True,
            last_received_quote=self.current_time - 5,  # Timed out (5s ago)
            operational_state=None,
        )
        self._create_push_agent(
            agent_id="timed-out-2",
            accept_attestations=True,
            last_received_quote=self.current_time - 20,  # Timed out (20s ago)
            operational_state=None,
        )
        self._create_push_agent(
            agent_id="never-connected",
            accept_attestations=True,
            last_received_quote=None,  # Never received
            operational_state=None,
        )

        # Run timeout check
        check_push_agent_timeouts()

        # Verify each agent's state
        healthy_1 = self.session.query(VerfierMain).filter_by(agent_id="healthy-1").first()
        assert healthy_1 is not None  # Type narrowing for pyright
        self.assertTrue(healthy_1.accept_attestations)

        healthy_2 = self.session.query(VerfierMain).filter_by(agent_id="healthy-2").first()
        assert healthy_2 is not None  # Type narrowing for pyright
        self.assertTrue(healthy_2.accept_attestations)

        timed_out_1 = self.session.query(VerfierMain).filter_by(agent_id="timed-out-1").first()
        assert timed_out_1 is not None  # Type narrowing for pyright
        self.assertFalse(timed_out_1.accept_attestations)

        timed_out_2 = self.session.query(VerfierMain).filter_by(agent_id="timed-out-2").first()
        assert timed_out_2 is not None  # Type narrowing for pyright
        self.assertFalse(timed_out_2.accept_attestations)

        never_connected = self.session.query(VerfierMain).filter_by(agent_id="never-connected").first()
        assert never_connected is not None  # Type narrowing for pyright
        self.assertTrue(never_connected.accept_attestations)

    def test_timeout_threshold_calculation(self):
        """Test that the timeout threshold is calculated correctly."""
        # Test with different quote_interval values
        test_intervals = [1.0, 2.0, 5.0, 10.0]

        for interval in test_intervals:
            with self.subTest(quote_interval=interval):
                expected_threshold = get_maximum_attestation_interval(interval)
                # The threshold should be 2x the quote_interval
                self.assertEqual(expected_threshold, interval * 2.0)

    def test_is_push_mode_agent(self):
        """Test the is_push_mode_agent() function with various agent configurations."""
        # Test case 1: operational_state is None → PUSH mode
        agent1 = self._create_push_agent(
            agent_id="push-agent-1",
            operational_state=None,
            ip="192.168.1.100",  # Has IP but operational_state is None
            port=9002,  # Has port but operational_state is None
        )
        self.assertTrue(is_push_mode_agent(agent1))

        # Test case 2: ip and port are None (regardless of operational_state) → PUSH mode
        agent2 = self._create_push_agent(
            agent_id="push-agent-2",
            operational_state=7,  # Has operational_state
            ip=None,  # No IP
            port=None,  # No port
        )
        self.assertTrue(is_push_mode_agent(agent2))

        # Test case 3: operational_state is None, ip and port are None → PUSH mode
        agent3 = self._create_push_agent(
            agent_id="push-agent-3",
            operational_state=None,
            ip=None,
            port=None,
        )
        self.assertTrue(is_push_mode_agent(agent3))

        # Test case 4: Has operational_state, ip, and port → PULL mode
        agent4 = self._create_push_agent(
            agent_id="pull-agent-1",
            operational_state=7,
            ip="127.0.0.1",
            port=9002,
        )
        self.assertFalse(is_push_mode_agent(agent4))

        # Test case 5: Has operational_state and ip but no port → PULL mode (edge case)
        # This shouldn't happen in practice but testing the logic
        agent5 = self._create_push_agent(
            agent_id="edge-agent-1",
            operational_state=7,
            ip="127.0.0.1",
            port=None,  # Port is None but ip is set
        )
        self.assertFalse(is_push_mode_agent(agent5))  # Not PUSH because ip is not None

    # ===== Event-Driven Timeout Tests =====

    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    @patch("keylime.push_agent_monitor.config")
    def test_schedule_timeout_with_default_timeout(self, mock_config, mock_ioloop_class):
        """Test scheduling a timeout with default timeout calculation."""
        # Configure mocks
        quote_interval = 2.0
        mock_config.getfloat.return_value = quote_interval

        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop
        mock_timeout_handle = Mock()
        mock_ioloop.call_later.return_value = mock_timeout_handle

        # Schedule timeout
        schedule_agent_timeout("test-agent-1")

        # Verify config was queried
        mock_config.getfloat.assert_called_once_with("verifier", "quote_interval", fallback=2.0)

        # Verify timeout was scheduled with correct parameters
        expected_timeout = get_maximum_attestation_interval(quote_interval)
        mock_ioloop.call_later.assert_called_once()
        call_args = mock_ioloop.call_later.call_args
        self.assertEqual(call_args[0][0], expected_timeout)  # timeout_seconds
        # Note: callback is now a lambda, so we can't check it directly
        self.assertTrue(callable(call_args[0][1]))  # callback function is callable

        # Verify handle was stored
        self.assertIn("test-agent-1", _agent_timeout_handles)
        self.assertEqual(_agent_timeout_handles["test-agent-1"], mock_timeout_handle)

    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    @patch("keylime.push_agent_monitor.config")
    def test_schedule_timeout_with_custom_timeout(self, _mock_config, mock_ioloop_class):
        """Test scheduling a timeout with a custom timeout value."""
        # Configure mocks
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop
        mock_timeout_handle = Mock()
        mock_ioloop.call_later.return_value = mock_timeout_handle

        # Schedule timeout with custom value
        custom_timeout = 15.5
        schedule_agent_timeout("test-agent-2", timeout_seconds=custom_timeout)

        # Verify timeout was scheduled with custom timeout
        mock_ioloop.call_later.assert_called_once()
        call_args = mock_ioloop.call_later.call_args
        self.assertEqual(call_args[0][0], custom_timeout)
        # Note: callback is now a lambda, so we can't check it directly
        self.assertTrue(callable(call_args[0][1]))  # callback function is callable

        # Verify handle was stored
        self.assertIn("test-agent-2", _agent_timeout_handles)
        self.assertEqual(_agent_timeout_handles["test-agent-2"], mock_timeout_handle)

    @patch("keylime.push_agent_monitor.cancel_agent_timeout")
    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    @patch("keylime.push_agent_monitor.config")
    def test_schedule_timeout_cancels_existing(self, mock_config, mock_ioloop_class, mock_cancel):
        """Test that scheduling a timeout cancels any existing timeout for the same agent."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop
        mock_ioloop.call_later.return_value = Mock()

        # Schedule timeout
        schedule_agent_timeout("test-agent-3")

        # Verify cancel was called first
        mock_cancel.assert_called_once_with("test-agent-3")

    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    @patch("keylime.push_agent_monitor.config")
    def test_schedule_timeout_multiple_agents(self, mock_config, mock_ioloop_class):
        """Test scheduling timeouts for multiple agents."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop

        # Create different handles for each agent
        handle1, handle2, handle3 = Mock(), Mock(), Mock()
        mock_ioloop.call_later.side_effect = [handle1, handle2, handle3]

        # Schedule timeouts for multiple agents
        schedule_agent_timeout("agent-1")
        schedule_agent_timeout("agent-2")
        schedule_agent_timeout("agent-3")

        # Verify all handles are stored
        self.assertEqual(len(_agent_timeout_handles), 3)
        self.assertEqual(_agent_timeout_handles["agent-1"], handle1)
        self.assertEqual(_agent_timeout_handles["agent-2"], handle2)
        self.assertEqual(_agent_timeout_handles["agent-3"], handle3)

    @patch("keylime.push_agent_monitor.logger")
    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    def test_schedule_timeout_handles_exception(self, mock_ioloop_class, mock_logger):
        """Test that exceptions during scheduling are caught and logged."""
        # Configure mock to raise exception
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop
        mock_ioloop.call_later.side_effect = RuntimeError("Test error")

        # Schedule timeout - should not raise
        schedule_agent_timeout("test-agent-4", timeout_seconds=10.0)

        # Verify error was logged
        mock_logger.error.assert_called_once()
        mock_logger.exception.assert_called_once()

        # Verify handle was not stored
        self.assertNotIn("test-agent-4", _agent_timeout_handles)

    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    def test_cancel_existing_timeout(self, mock_ioloop_class):
        """Test cancelling an existing timeout."""
        # Set up mock
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop

        # Add a timeout handle
        mock_handle = Mock()
        _agent_timeout_handles["test-agent-1"] = mock_handle

        # Cancel timeout
        cancel_agent_timeout("test-agent-1")

        # Verify timeout was removed from IOLoop
        mock_ioloop.remove_timeout.assert_called_once_with(mock_handle)

        # Verify handle was removed from dict
        self.assertNotIn("test-agent-1", _agent_timeout_handles)

    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    def test_cancel_nonexistent_timeout(self, mock_ioloop_class):
        """Test cancelling a timeout that doesn't exist (should be a no-op)."""
        # Set up mock
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop

        # Cancel timeout that doesn't exist - should not raise
        cancel_agent_timeout("nonexistent-agent")

        # Verify remove_timeout was NOT called
        mock_ioloop.remove_timeout.assert_not_called()

    @patch("keylime.push_agent_monitor.logger")
    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    def test_cancel_timeout_handles_exception(self, mock_ioloop_class, mock_logger):
        """Test that exceptions during cancellation are caught and logged."""
        # Set up mock to raise exception
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop
        mock_ioloop.remove_timeout.side_effect = RuntimeError("Test error")

        # Add a timeout handle
        mock_handle = Mock()
        _agent_timeout_handles["test-agent-2"] = mock_handle

        # Cancel timeout - should not raise
        cancel_agent_timeout("test-agent-2")

        # Verify error was logged
        mock_logger.error.assert_called_once()

        # Verify handle was removed from dict even though removal failed
        self.assertNotIn("test-agent-2", _agent_timeout_handles)

    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    def test_cancel_multiple_timeouts(self, mock_ioloop_class):
        """Test cancelling multiple timeouts."""
        # Set up mock
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop

        # Add multiple timeout handles
        handle1, handle2, handle3 = Mock(), Mock(), Mock()
        _agent_timeout_handles["agent-1"] = handle1
        _agent_timeout_handles["agent-2"] = handle2
        _agent_timeout_handles["agent-3"] = handle3

        # Cancel all timeouts
        cancel_agent_timeout("agent-1")
        cancel_agent_timeout("agent-2")
        cancel_agent_timeout("agent-3")

        # Verify all were removed from IOLoop
        self.assertEqual(mock_ioloop.remove_timeout.call_count, 3)
        mock_ioloop.remove_timeout.assert_has_calls([call(handle1), call(handle2), call(handle3)], any_order=True)

        # Verify all handles removed from dict
        self.assertEqual(len(_agent_timeout_handles), 0)

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_mark_agent_failed_success(self, mock_session_context, mock_config):
        """Test successfully marking an agent as failed."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None

        # Create agent
        self._create_push_agent("test-agent-1", accept_attestations=True)

        # Add to timeout handles
        mock_handle = Mock()
        _agent_timeout_handles["test-agent-1"] = mock_handle

        # Mark agent as failed
        _mark_agent_failed("test-agent-1", mock_handle)

        # Verify agent was marked as failed
        agent = self.session.query(VerfierMain).filter_by(agent_id="test-agent-1").first()
        self.assertIsNotNone(agent)
        assert agent is not None  # Type narrowing
        self.assertFalse(agent.accept_attestations)

        # Verify handle was removed
        self.assertNotIn("test-agent-1", _agent_timeout_handles)

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_mark_agent_failed_already_failed(self, mock_session_context, mock_config):
        """Test marking an already-failed agent (should be a no-op)."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None

        # Create agent that's already failed
        self._create_push_agent("test-agent-2", accept_attestations=False)

        # Mark agent as failed
        mock_handle = Mock()
        _mark_agent_failed("test-agent-2", mock_handle)

        # Verify agent is still marked as failed (no change)
        agent = self.session.query(VerfierMain).filter_by(agent_id="test-agent-2").first()
        self.assertIsNotNone(agent)
        assert agent is not None  # Type narrowing
        self.assertFalse(agent.accept_attestations)

    @patch("keylime.push_agent_monitor.logger")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_mark_agent_failed_agent_not_found(self, mock_session_context, mock_logger):
        """Test marking an agent that doesn't exist in the database."""
        # Configure mocks
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None

        # Add to timeout handles
        mock_handle = Mock()
        _agent_timeout_handles["nonexistent-agent"] = mock_handle

        # Mark nonexistent agent as failed - should not raise
        _mark_agent_failed("nonexistent-agent", mock_handle)

        # Verify warning was logged
        mock_logger.warning.assert_called_once()
        self.assertIn("not found in database", mock_logger.warning.call_args[0][0])

        # Verify handle was still removed
        self.assertNotIn("nonexistent-agent", _agent_timeout_handles)

    @patch("keylime.push_agent_monitor.logger")
    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_mark_agent_failed_logs_timeout_info(self, mock_session_context, mock_config, mock_logger):
        """Test that marking an agent as failed logs appropriate information."""
        # Configure mocks
        quote_interval = 2.0
        mock_config.getfloat.return_value = quote_interval
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None

        # Create agent
        self._create_push_agent("test-agent-3", accept_attestations=True)

        # Add to timeout handles
        mock_handle = Mock()
        _agent_timeout_handles["test-agent-3"] = mock_handle

        # Mark agent as failed
        _mark_agent_failed("test-agent-3", mock_handle)

        # Verify warning was logged with timeout information
        mock_logger.warning.assert_called_once()
        warning_msg = mock_logger.warning.call_args[0][0]
        self.assertIn("timed out", warning_msg)
        self.assertIn("test-agent-3", mock_logger.warning.call_args[0][1])

        # Verify timeout seconds is correct
        expected_timeout = get_maximum_attestation_interval(quote_interval)
        self.assertEqual(mock_logger.warning.call_args[0][2], expected_timeout)

    @patch("keylime.push_agent_monitor.logger")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_mark_agent_failed_handles_exception(self, mock_session_context, mock_logger):
        """Test that exceptions during mark_agent_failed are caught and logged."""
        # Configure mock to raise exception
        mock_session_context.side_effect = RuntimeError("Database connection error")

        # Add to timeout handles
        mock_handle = Mock()
        _agent_timeout_handles["test-agent-4"] = mock_handle

        # Mark agent as failed - should not raise
        _mark_agent_failed("test-agent-4", mock_handle)

        # Verify error was logged
        mock_logger.error.assert_called_once()
        mock_logger.exception.assert_called_once()

        # Verify handle was still removed
        self.assertNotIn("test-agent-4", _agent_timeout_handles)

    @patch("keylime.push_agent_monitor.config")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_mark_agent_failed_removes_handle_before_db_update(self, mock_session_context, mock_config):
        """Test that the timeout handle is removed before attempting database update."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_session_context.return_value.__enter__.return_value = self.session
        mock_session_context.return_value.__exit__.return_value = None

        # Create agent
        self._create_push_agent("test-agent-5", accept_attestations=True)

        # Add to timeout handles
        mock_handle = Mock()
        _agent_timeout_handles["test-agent-5"] = mock_handle

        # Mark agent as failed
        _mark_agent_failed("test-agent-5", mock_handle)

        # Verify handle was removed (even before we check the database result)
        self.assertNotIn("test-agent-5", _agent_timeout_handles)

    @patch("keylime.push_agent_monitor.tornado.ioloop.IOLoop")
    @patch("keylime.push_agent_monitor.config")
    def test_reschedule_updates_handle(self, mock_config, mock_ioloop_class):
        """Test that rescheduling a timeout updates the handle."""
        # Configure mocks
        mock_config.getfloat.return_value = 2.0
        mock_ioloop = MagicMock()
        mock_ioloop_class.current.return_value = mock_ioloop

        # Create different handles
        old_handle, new_handle = Mock(), Mock()
        mock_ioloop.call_later.side_effect = [old_handle, new_handle]

        # Schedule timeout
        schedule_agent_timeout("agent-1")
        self.assertEqual(_agent_timeout_handles["agent-1"], old_handle)

        # Reschedule timeout
        schedule_agent_timeout("agent-1")

        # Verify handle was updated
        self.assertEqual(_agent_timeout_handles["agent-1"], new_handle)
        self.assertNotEqual(_agent_timeout_handles["agent-1"], old_handle)

    def test_handles_isolated_between_agents(self):
        """Test that timeout handles are properly isolated between agents."""
        # Add handles for different agents
        handle1, handle2, handle3 = Mock(), Mock(), Mock()
        _agent_timeout_handles["agent-1"] = handle1
        _agent_timeout_handles["agent-2"] = handle2
        _agent_timeout_handles["agent-3"] = handle3

        # Verify handles are isolated
        self.assertEqual(_agent_timeout_handles["agent-1"], handle1)
        self.assertEqual(_agent_timeout_handles["agent-2"], handle2)
        self.assertEqual(_agent_timeout_handles["agent-3"], handle3)

        # Remove one handle
        removed_handle = _agent_timeout_handles.pop("agent-2")
        self.assertEqual(removed_handle, handle2)

        # Verify others are unaffected
        self.assertEqual(_agent_timeout_handles["agent-1"], handle1)
        self.assertEqual(_agent_timeout_handles["agent-3"], handle3)
        self.assertNotIn("agent-2", _agent_timeout_handles)


if __name__ == "__main__":
    unittest.main()
