"""Unit tests for cloud_verifier_tornado deletion and pending-event management.

Tests cover:
1. _register_pending_event / _cancel_pending_event helpers
2. store_attestation_state graceful handling when agent is deleted
"""

# pylint: disable=protected-access

import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy.exc import SQLAlchemyError

from keylime import cloud_verifier_tornado


class TestPendingEventRegistry(unittest.TestCase):
    """Test the _pending_events registry helpers."""

    def setUp(self):
        cloud_verifier_tornado._pending_events.clear()

    def tearDown(self):
        cloud_verifier_tornado._pending_events.clear()

    def test_register_pending_event(self):
        """_register_pending_event stores handle in agent dict and global registry."""
        agent = {"agent_id": "test-agent-1", "pending_event": None}
        handle = object()

        cloud_verifier_tornado._register_pending_event(agent, handle)

        self.assertIs(agent["pending_event"], handle)
        self.assertIs(cloud_verifier_tornado._pending_events["test-agent-1"], handle)

    def test_cancel_pending_event_removes_from_both(self):
        """_cancel_pending_event clears agent dict and global registry."""
        agent = {"agent_id": "test-agent-1", "pending_event": None}
        handle = object()
        cloud_verifier_tornado._register_pending_event(agent, handle)

        with patch("tornado.ioloop.IOLoop") as mock_ioloop_cls:
            mock_ioloop = MagicMock()
            mock_ioloop_cls.current.return_value = mock_ioloop

            cloud_verifier_tornado._cancel_pending_event(agent)

        self.assertIsNone(agent["pending_event"])
        self.assertNotIn("test-agent-1", cloud_verifier_tornado._pending_events)
        mock_ioloop.remove_timeout.assert_called_once_with(handle)

    def test_cancel_pending_event_noop_when_none(self):
        """_cancel_pending_event is a no-op when no pending event exists."""
        agent = {"agent_id": "test-agent-1", "pending_event": None}

        # Should not raise
        cloud_verifier_tornado._cancel_pending_event(agent)

        self.assertIsNone(agent["pending_event"])

    def test_cancel_pending_event_handles_remove_timeout_error(self):
        """_cancel_pending_event logs but doesn't raise on remove_timeout failure."""
        agent = {"agent_id": "test-agent-1", "pending_event": None}
        handle = object()
        cloud_verifier_tornado._register_pending_event(agent, handle)

        with patch("tornado.ioloop.IOLoop") as mock_ioloop_cls:
            mock_ioloop = MagicMock()
            mock_ioloop_cls.current.return_value = mock_ioloop
            mock_ioloop.remove_timeout.side_effect = RuntimeError("IOLoop stopped")

            # Should not raise
            cloud_verifier_tornado._cancel_pending_event(agent)

        self.assertIsNone(agent["pending_event"])
        self.assertNotIn("test-agent-1", cloud_verifier_tornado._pending_events)

    def test_register_replaces_previous_handle(self):
        """_register_pending_event replaces a previously registered handle."""
        agent = {"agent_id": "test-agent-1", "pending_event": None}
        handle1 = object()
        handle2 = object()

        cloud_verifier_tornado._register_pending_event(agent, handle1)
        cloud_verifier_tornado._register_pending_event(agent, handle2)

        self.assertIs(agent["pending_event"], handle2)
        self.assertIs(cloud_verifier_tornado._pending_events["test-agent-1"], handle2)


class TestStoreAttestationState(unittest.TestCase):
    """Test store_attestation_state graceful handling of deleted agents."""

    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_skips_when_agent_not_in_db(self, mock_session_ctx):
        """store_attestation_state returns gracefully when agent is deleted from DB."""
        mock_session = MagicMock()
        mock_session.get.return_value = None
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        mock_attest_state = MagicMock()
        mock_attest_state.get_ima_pcrs.return_value = {"10": "some_value"}
        mock_attest_state.agent_id = "deleted-agent"
        mock_attest_state.get_agent_id.return_value = "deleted-agent"

        # Should not raise (previously would AssertionError)
        cloud_verifier_tornado.store_attestation_state(mock_attest_state)

        # Verify no attempt to set attributes on None
        mock_session.add.assert_not_called()


class TestCompleteDeletionIfTerminated(unittest.TestCase):
    """Test _complete_deletion_if_terminated helper."""

    @patch("keylime.cloud_verifier_tornado.verifier_db_delete_agent")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_deletes_when_agent_is_terminated(self, mock_session_ctx, mock_delete):
        """Completes deletion when agent exists and is TERMINATED."""
        mock_session = MagicMock()
        mock_agent = MagicMock()
        mock_agent.operational_state = 8  # states.TERMINATED
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_agent
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        cloud_verifier_tornado._complete_deletion_if_terminated("agent-123")

        mock_delete.assert_called_once_with(mock_session, "agent-123")

    @patch("keylime.cloud_verifier_tornado.verifier_db_delete_agent")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_noop_when_agent_already_deleted(self, mock_session_ctx, mock_delete):
        """Logs and returns when agent no longer exists in DB."""
        mock_session = MagicMock()
        mock_session.query.return_value.filter_by.return_value.first.return_value = None
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        cloud_verifier_tornado._complete_deletion_if_terminated("agent-123")

        mock_delete.assert_not_called()

    @patch("keylime.cloud_verifier_tornado.logger")
    @patch("keylime.cloud_verifier_tornado.verifier_db_delete_agent")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_warns_when_agent_in_unexpected_state(self, mock_session_ctx, mock_delete, mock_logger):
        """Logs warning and does not delete when agent exists in a non-TERMINATED state."""
        mock_session = MagicMock()
        mock_agent = MagicMock()
        mock_agent.operational_state = 3  # states.GET_QUOTE
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_agent
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        cloud_verifier_tornado._complete_deletion_if_terminated("agent-123")

        mock_delete.assert_not_called()
        mock_logger.warning.assert_called_once()

    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_handles_sqlalchemy_error(self, mock_session_ctx):
        """Logs and does not raise on SQLAlchemyError."""
        mock_session_ctx.return_value.__enter__ = MagicMock(side_effect=SQLAlchemyError("connection lost"))
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        cloud_verifier_tornado._complete_deletion_if_terminated("agent-123")


if __name__ == "__main__":
    unittest.main()
