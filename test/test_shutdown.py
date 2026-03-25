"""Unit tests for the shutdown coordination module and verifier drain logic."""

# pylint: disable=protected-access,import-outside-toplevel

import asyncio
import unittest
from unittest.mock import patch

from keylime import shutdown


class TestShutdownFlag(unittest.TestCase):
    """Test the process-wide shutdown flag."""

    def setUp(self) -> None:
        # Reset the module-level event before each test
        shutdown._shutdown_event = asyncio.Event()

    def test_initial_state_not_shutting_down(self) -> None:
        self.assertFalse(shutdown.is_shutting_down())

    def test_request_shutdown_sets_flag(self) -> None:
        shutdown.request_shutdown()
        self.assertTrue(shutdown.is_shutting_down())

    def test_request_shutdown_is_idempotent(self) -> None:
        shutdown.request_shutdown()
        shutdown.request_shutdown()
        self.assertTrue(shutdown.is_shutting_down())


class TestOperationTracking(unittest.TestCase):
    """Test _enter_operation / _exit_operation and drain logic."""

    def setUp(self) -> None:
        # Import here so we can reset module globals
        from keylime import cloud_verifier_tornado as cvt

        self.cvt = cvt
        # Save and reset module state
        self._saved_active = cvt._active_operations
        self._saved_event = cvt._operations_drained
        cvt._active_operations = 0
        cvt._operations_drained = asyncio.Event()
        cvt._operations_drained.set()

    def tearDown(self) -> None:
        self.cvt._active_operations = self._saved_active
        self.cvt._operations_drained = self._saved_event

    def test_initial_state_is_drained(self) -> None:
        self.assertEqual(self.cvt.get_active_operations(), 0)
        self.assertTrue(self.cvt._operations_drained.is_set())

    def test_enter_increments_and_clears_drain(self) -> None:
        self.cvt._enter_operation()
        self.assertEqual(self.cvt.get_active_operations(), 1)
        self.assertFalse(self.cvt._operations_drained.is_set())

    def test_exit_decrements_and_signals_drain(self) -> None:
        self.cvt._enter_operation()
        self.cvt._exit_operation()
        self.assertEqual(self.cvt.get_active_operations(), 0)
        self.assertTrue(self.cvt._operations_drained.is_set())

    def test_multiple_operations_drain_on_last_exit(self) -> None:
        self.cvt._enter_operation()
        self.cvt._enter_operation()
        self.assertEqual(self.cvt.get_active_operations(), 2)
        self.assertFalse(self.cvt._operations_drained.is_set())

        self.cvt._exit_operation()
        self.assertEqual(self.cvt.get_active_operations(), 1)
        self.assertFalse(self.cvt._operations_drained.is_set())

        self.cvt._exit_operation()
        self.assertEqual(self.cvt.get_active_operations(), 0)
        self.assertTrue(self.cvt._operations_drained.is_set())

    def test_wait_for_drain_returns_true_when_already_drained(self) -> None:
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self.cvt.wait_for_drain(1.0))
            self.assertTrue(result)
        finally:
            loop.close()

    def test_wait_for_drain_returns_true_after_exit(self) -> None:
        self.cvt._enter_operation()

        async def _drain_after_delay() -> bool:
            async def _exit_soon() -> None:
                await asyncio.sleep(0.05)
                self.cvt._exit_operation()

            asyncio.ensure_future(_exit_soon())
            return await self.cvt.wait_for_drain(2.0)

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_drain_after_delay())
            self.assertTrue(result)
            self.assertEqual(self.cvt.get_active_operations(), 0)
        finally:
            loop.close()

    def test_wait_for_drain_returns_false_on_timeout(self) -> None:
        self.cvt._enter_operation()

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self.cvt.wait_for_drain(0.1))
            self.assertFalse(result)
        finally:
            loop.close()


class TestPendingEventRegistry(unittest.TestCase):
    """Test _register_pending_event / _cancel_pending_event / cancel_all."""

    def setUp(self) -> None:
        from keylime import cloud_verifier_tornado as cvt

        self.cvt = cvt
        self._saved_pending = dict(cvt._pending_events)
        cvt._pending_events.clear()

    def tearDown(self) -> None:
        self.cvt._pending_events.clear()
        self.cvt._pending_events.update(self._saved_pending)

    def _make_agent(self, agent_id: str = "test-agent-1") -> dict:
        return {"agent_id": agent_id, "pending_event": None}

    def test_register_tracks_in_both_locations(self) -> None:
        agent = self._make_agent()
        handle = object()
        self.cvt._register_pending_event(agent, handle)

        self.assertIs(agent["pending_event"], handle)
        self.assertIs(self.cvt._pending_events["test-agent-1"], handle)

    def test_cancel_clears_both_locations(self) -> None:
        agent = self._make_agent()
        handle = object()
        self.cvt._register_pending_event(agent, handle)

        with patch("tornado.ioloop.IOLoop.current"):
            self.cvt._cancel_pending_event(agent)

        self.assertIsNone(agent["pending_event"])
        self.assertNotIn("test-agent-1", self.cvt._pending_events)

    def test_cancel_noop_when_no_pending_event(self) -> None:
        agent = self._make_agent()
        # Should not raise
        self.cvt._cancel_pending_event(agent)
        self.assertIsNone(agent["pending_event"])

    def test_cancel_all_clears_registry(self) -> None:
        agents = [self._make_agent(f"agent-{i}") for i in range(3)]
        for i, agent in enumerate(agents):
            self.cvt._register_pending_event(agent, object())

        self.assertEqual(len(self.cvt._pending_events), 3)

        with patch("tornado.ioloop.IOLoop.current"):
            self.cvt.cancel_all_pending_events()

        self.assertEqual(len(self.cvt._pending_events), 0)

    def test_cancel_all_noop_when_empty(self) -> None:
        # Should not raise
        self.cvt.cancel_all_pending_events()


class TestPushAgentMonitorCancelAll(unittest.TestCase):
    """Test cancel_all_timeouts in push_agent_monitor."""

    def setUp(self) -> None:
        from keylime import push_agent_monitor

        self.pam = push_agent_monitor
        with self.pam._agent_timeout_handles_lock:
            self._saved = dict(self.pam._agent_timeout_handles)
            self.pam._agent_timeout_handles.clear()

    def tearDown(self) -> None:
        with self.pam._agent_timeout_handles_lock:
            self.pam._agent_timeout_handles.clear()
            self.pam._agent_timeout_handles.update(self._saved)

    def test_cancel_all_clears_handles(self) -> None:
        with self.pam._agent_timeout_handles_lock:
            self.pam._agent_timeout_handles["a1"] = object()
            self.pam._agent_timeout_handles["a2"] = object()

        with patch("tornado.ioloop.IOLoop.current"):
            self.pam.cancel_all_timeouts()

        with self.pam._agent_timeout_handles_lock:
            self.assertEqual(len(self.pam._agent_timeout_handles), 0)

    def test_cancel_all_noop_when_empty(self) -> None:
        # Should not raise
        self.pam.cancel_all_timeouts()


if __name__ == "__main__":
    unittest.main()
