"""Unit tests for cloud_verifier_tornado deletion and pending-event management.

Tests cover:
1. _register_pending_event / _cancel_pending_event helpers
2. store_attestation_state graceful handling when agent is deleted
3. AgentsHandler.get() race condition: session.refresh() raises InvalidRequestError
   when the attestation loop deletes the agent between query and refresh
"""

# pylint: disable=protected-access

import asyncio
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from sqlalchemy.exc import InvalidRequestError, SQLAlchemyError

from keylime import cloud_verifier_tornado
from keylime.common import states


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
        mock_query_chain = MagicMock()
        mock_query_chain.filter_by.return_value = mock_query_chain
        mock_query_chain.filter.return_value = mock_query_chain
        mock_query_chain.first.return_value = None
        mock_session.query.return_value = mock_query_chain
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        mock_attest_state = MagicMock()
        mock_attest_state.get_ima_pcrs.return_value = {"10": "some_value"}
        mock_attest_state.agent_id = "deleted-agent"
        mock_attest_state.get_agent_id.return_value = "deleted-agent"

        # Should not raise
        cloud_verifier_tornado.store_attestation_state(mock_attest_state)

        # Verify no attempt to set attributes on None
        mock_session.add.assert_not_called()

    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_skips_when_generation_mismatches(self, mock_session_ctx):
        """store_attestation_state skips write when enrollment generation doesn't match."""
        mock_session = MagicMock()
        mock_query_chain = MagicMock()
        mock_query_chain.filter_by.return_value = mock_query_chain
        mock_query_chain.filter.return_value = mock_query_chain
        mock_query_chain.first.return_value = None  # generation filter excludes the row
        mock_session.query.return_value = mock_query_chain
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        mock_attest_state = MagicMock()
        mock_attest_state.get_ima_pcrs.return_value = {"10": "some_value"}
        mock_attest_state.agent_id = "stale-agent"
        mock_attest_state.get_agent_id.return_value = "stale-agent"

        cloud_verifier_tornado.store_attestation_state(mock_attest_state, expected_generation=0)

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
    def test_noop_when_agent_tenant_failed(self, mock_session_ctx, mock_delete, mock_logger):
        """Does not delete when agent is in TENANT_FAILED state."""
        mock_session = MagicMock()
        mock_agent = MagicMock()
        mock_agent.operational_state = 10  # states.TENANT_FAILED
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_agent
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        cloud_verifier_tornado._complete_deletion_if_terminated("agent-123")

        mock_delete.assert_not_called()
        mock_logger.info.assert_called_once()
        self.assertIn("tenant quote check failed", mock_logger.info.call_args[0][0])

    @patch("keylime.cloud_verifier_tornado.logger")
    @patch("keylime.cloud_verifier_tornado.verifier_db_delete_agent")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_warns_when_agent_in_unexpected_state(self, mock_session_ctx, mock_delete, mock_logger):
        """Logs warning and does not delete when agent exists in an unexpected state."""
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


class TestCheckPushAgentTimeoutOnStartup(unittest.TestCase):
    """Tests for check_push_agent_timeout_on_startup()."""

    def _make_agent(
        self,
        agent_id="agent-1",
        operational_state=None,
        ip=None,
        port=None,
        accept_attestations=True,
        last_received_quote=None,
    ):
        agent = MagicMock()
        agent.agent_id = agent_id
        agent.operational_state = operational_state
        agent.ip = ip
        agent.port = port
        agent.accept_attestations = accept_attestations
        agent.last_received_quote = last_received_quote
        return agent

    def test_pull_agent_ignored(self):
        """PULL mode agents are not checked for timeout."""
        agent = self._make_agent(ip="10.0.0.1", port=9002, operational_state=7)
        result = cloud_verifier_tornado.check_push_agent_timeout_on_startup(agent, 1000, 10.0)
        self.assertFalse(result)

    def test_push_agent_timed_out(self):
        """PUSH agent with old last_received_quote is marked timed out."""
        agent = self._make_agent(last_received_quote=900, accept_attestations=True)
        result = cloud_verifier_tornado.check_push_agent_timeout_on_startup(agent, 1000, 10.0)
        self.assertTrue(result)
        self.assertFalse(agent.accept_attestations)

    def test_push_agent_still_healthy(self):
        """PUSH agent with recent last_received_quote is not marked timed out."""
        agent = self._make_agent(last_received_quote=995, accept_attestations=True)
        result = cloud_verifier_tornado.check_push_agent_timeout_on_startup(agent, 1000, 10.0)
        self.assertFalse(result)
        self.assertTrue(agent.accept_attestations)

    def test_push_agent_no_quote_yet(self):
        """PUSH agent with no last_received_quote is not marked timed out."""
        agent = self._make_agent(last_received_quote=None, accept_attestations=True)
        result = cloud_verifier_tornado.check_push_agent_timeout_on_startup(agent, 1000, 10.0)
        self.assertFalse(result)

    def test_push_agent_sentinel_zero_not_timed_out(self):
        """PUSH agent with sentinel last_received_quote=0 is not marked timed out."""
        agent = self._make_agent(last_received_quote=0, accept_attestations=True)
        result = cloud_verifier_tornado.check_push_agent_timeout_on_startup(agent, 1000, 10.0)
        self.assertFalse(result)
        self.assertTrue(agent.accept_attestations)

    def test_push_agent_already_timed_out(self):
        """PUSH agent already marked as timed out (accept_attestations=False) is not changed."""
        agent = self._make_agent(last_received_quote=900, accept_attestations=False)
        result = cloud_verifier_tornado.check_push_agent_timeout_on_startup(agent, 1000, 10.0)
        self.assertFalse(result)
        self.assertFalse(agent.accept_attestations)


class TestActivateAgentsSkipsPushMode(unittest.IsolatedAsyncioTestCase):
    """Tests for activate_agents() PUSH mode skip behavior."""

    @patch("keylime.cloud_verifier_tornado.get_AgentAttestStates")
    @patch("keylime.cloud_verifier_tornado._from_db_obj")
    @patch("keylime.cloud_verifier_tornado.agent_util.is_push_mode_agent")
    async def test_push_agents_skipped_pull_agents_activated(self, mock_is_push, mock_from_db, _mock_get_aas):
        """PUSH mode agents should be skipped during PULL activation."""
        push_agent = MagicMock()
        push_agent.agent_id = "push-agent"

        pull_agent = MagicMock()
        pull_agent.agent_id = "pull-agent"
        pull_agent.operational_state = None
        pull_agent.boottime = None

        mock_is_push.side_effect = lambda a: a.agent_id == "push-agent"
        mock_from_db.return_value = {"mtls_cert": None, "agent_id": "pull-agent"}

        await cloud_verifier_tornado.activate_agents([push_agent, pull_agent], "127.0.0.1", 8881)

        mock_from_db.assert_called_once_with(pull_agent)

    @patch("keylime.cloud_verifier_tornado.get_AgentAttestStates")
    @patch("keylime.cloud_verifier_tornado._from_db_obj")
    @patch("keylime.cloud_verifier_tornado.agent_util.is_push_mode_agent")
    async def test_all_push_agents_skipped(self, mock_is_push, mock_from_db, _mock_get_aas):
        """When all agents are PUSH mode, none should be activated."""
        agent1 = MagicMock()
        agent1.agent_id = "push-1"
        agent2 = MagicMock()
        agent2.agent_id = "push-2"

        mock_is_push.return_value = True

        await cloud_verifier_tornado.activate_agents([agent1, agent2], "127.0.0.1", 8881)

        mock_from_db.assert_not_called()


def _make_agents_handler(agent_id: str):
    """Build a bare AgentsHandler instance without Tornado infrastructure.

    Bypasses tornado.web.RequestHandler.__init__ and sets only the attributes
    the GET handler path under test actually touches.
    """
    handler = object.__new__(cloud_verifier_tornado.AgentsHandler)
    req = MagicMock()
    req.uri = f"/v2.1/agents/{agent_id}"
    handler._req_handler_override = req
    handler.request = req
    return handler


class TestGetHandlerRaceCondition(unittest.TestCase):
    """Verify that AgentsHandler.get() handles the concurrent-deletion race.

    The race: the attestation loop deletes a TERMINATED agent between the
    initial query (one_or_none) and the subsequent session.refresh(). SQLAlchemy
    raises InvalidRequestError("Could not refresh instance '...'") in that case.
    The handler must return 404 instead of propagating a 500.
    """

    AGENT_ID = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

    def _run_get(self, session_mock):
        """Wire up validate_input and session_context, invoke handler.get()."""
        handler = _make_agents_handler(self.AGENT_ID)

        # Provide REST params the same way __validate_input would
        validate_return = ({"agents": self.AGENT_ID, "api_version": "2.1"}, self.AGENT_ID)

        @contextmanager
        def fake_session_ctx():
            yield session_mock

        with (
            patch.object(
                cloud_verifier_tornado.AgentsHandler,
                "_AgentsHandler__validate_input",
                return_value=validate_return,
            ),
            patch("keylime.cloud_verifier_tornado.session_context", fake_session_ctx),
            patch("keylime.cloud_verifier_tornado.web_util.echo_json_response") as mock_echo,
        ):
            handler.get()
            return mock_echo

    def test_returns_404_when_refresh_raises_invalid_request_error(self):
        """GET returns 404 (not 500) when session.refresh raises InvalidRequestError."""
        mock_session = MagicMock()
        mock_agent = MagicMock()
        # Query finds the agent — it still existed at query time
        mock_session.query.return_value.options.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = (
            mock_agent
        )
        # Refresh raises — agent was deleted between query and refresh
        mock_session.refresh.side_effect = InvalidRequestError("Could not refresh instance")

        mock_echo = self._run_get(mock_session)

        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 404)
        self.assertIn("not found", args[2])
        # Verify attribute_names is passed to avoid expiring eagerly-loaded relationships
        mock_session.refresh.assert_called_once_with(mock_agent, attribute_names=["consecutive_attestation_failures"])

    def test_returns_200_when_no_race(self):
        """GET returns 200 normally when session.refresh succeeds."""
        mock_session = MagicMock()
        mock_agent = MagicMock()
        mock_session.query.return_value.options.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = (
            mock_agent
        )
        mock_session.refresh.return_value = None  # success

        with patch("keylime.cloud_verifier_tornado.cloud_verifier_common.process_get_status", return_value={}):
            mock_echo = self._run_get(mock_session)

        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 200)

    def test_returns_404_when_agent_not_found(self):
        """GET returns 404 when agent is not in DB at query time."""
        mock_session = MagicMock()
        mock_session.query.return_value.options.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = (
            None
        )

        mock_echo = self._run_get(mock_session)

        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 404)
        # refresh must NOT have been called — agent was already None
        mock_session.refresh.assert_not_called()

    def test_returns_404_when_agent_is_terminated(self):
        """GET returns 404 for a TERMINATED agent (tombstone pattern)."""
        mock_session = MagicMock()
        mock_agent = MagicMock()
        mock_agent.operational_state = states.TERMINATED
        mock_session.query.return_value.options.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = (
            mock_agent
        )
        mock_session.refresh.return_value = None  # success

        mock_echo = self._run_get(mock_session)

        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 404)
        self.assertIn("not found", args[2])


class TestBulkGetHandlerRaceCondition(unittest.TestCase):
    """Verify bulk GET skips deleted agents rather than crashing."""

    AGENT_IDS = ["agent-aaa", "agent-bbb", "agent-ccc"]

    def _run_bulk_get(self, session_mock):
        handler = _make_agents_handler("")

        # No agent_id → bulk listing path; "bulk" key triggers the for-loop
        validate_return = ({"agents": "", "api_version": "2.1", "bulk": ""}, "")

        @contextmanager
        def fake_session_ctx():
            yield session_mock

        with (
            patch.object(
                cloud_verifier_tornado.AgentsHandler,
                "_AgentsHandler__validate_input",
                return_value=validate_return,
            ),
            patch("keylime.cloud_verifier_tornado.session_context", fake_session_ctx),
            patch("keylime.cloud_verifier_tornado.web_util.echo_json_response") as mock_echo,
            patch(
                "keylime.cloud_verifier_tornado.cloud_verifier_common.process_get_status",
                side_effect=lambda a: {"agent_id": a.agent_id},
            ),
        ):
            handler.get()
            return mock_echo

    def test_bulk_get_skips_deleted_agent_includes_rest(self):
        """Bulk GET omits the concurrently-deleted agent but includes the others."""
        agents = []
        for aid in self.AGENT_IDS:
            a = MagicMock()
            a.agent_id = aid
            agents.append(a)

        mock_session = MagicMock()
        mock_session.query.return_value.options.return_value.options.return_value.all.return_value = agents

        # Middle agent is deleted between query and refresh
        def refresh_side_effect(agent, attribute_names=None):  # pylint: disable=unused-argument
            if agent.agent_id == "agent-bbb":
                raise InvalidRequestError("Could not refresh instance")

        mock_session.refresh.side_effect = refresh_side_effect

        mock_echo = self._run_bulk_get(mock_session)

        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 200)
        result = args[3]
        self.assertIn("agent-aaa", result)
        self.assertNotIn("agent-bbb", result)  # deleted agent is skipped
        self.assertIn("agent-ccc", result)

    def test_bulk_get_skips_terminated_agent(self):
        """Bulk GET omits TERMINATED agents (tombstone pattern)."""
        agents = []
        for aid in self.AGENT_IDS:
            a = MagicMock()
            a.agent_id = aid
            a.operational_state = states.GET_QUOTE  # normal state
            agents.append(a)
        # Mark middle agent as TERMINATED
        agents[1].operational_state = states.TERMINATED

        mock_session = MagicMock()
        mock_session.query.return_value.options.return_value.options.return_value.all.return_value = agents
        mock_session.refresh.return_value = None

        mock_echo = self._run_bulk_get(mock_session)

        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 200)
        result = args[3]
        self.assertIn("agent-aaa", result)
        self.assertNotIn("agent-bbb", result)  # TERMINATED agent is skipped
        self.assertIn("agent-ccc", result)


class TestPostHandlerTombstoneCleanup(unittest.TestCase):
    """Verify POST cleans up TERMINATED agents instead of returning 409.

    When an agent DELETE returns 202 (async), the row stays in DB with
    operational_state=TERMINATED until the attestation loop garbage-collects it.
    A subsequent POST to re-enroll the same agent_id must not return 409 —
    it should delete the TERMINATED row and proceed with enrollment.
    """

    AGENT_ID = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
    FULL_JSON_BODY = {
        "cloudagent_ip": "127.0.0.1",
        "cloudagent_port": "9002",
        "supported_version": "2.1",
        "mtls_cert": "disabled",
        "runtime_policy_name": "",
        "runtime_policy": "",
        "runtime_policy_key": "",
        "mb_policy": "",
        "mb_policy_name": "",
        "v": "test-v",
        "tpm_policy": "{}",
        "metadata": "{}",
        "ima_sign_verification_keys": "",
        "revocation_key": "",
        "accept_tpm_hash_algs": ["sha256"],
        "accept_tpm_encryption_algs": ["rsa"],
        "accept_tpm_signing_algs": ["rsassa"],
        "ak_tpm": "test-ak",
    }

    def _make_session_mock(self, agent_count, existing_agent=None):
        """Build a session mock that routes query() calls correctly.

        session.query(VerifierAllowlist) is used for IMA policy lookups.
        session.query(VerifierMbpolicy) is used for MB policy lookups.
        session.query(VerfierMain) is used for the agent duplicate check.
        """
        mock_session = MagicMock()

        allowlist_chain = MagicMock()
        allowlist_chain.filter_by.return_value.one_or_none.return_value = None

        mbpolicy_chain = MagicMock()
        mbpolicy_chain.filter_by.return_value.one_or_none.return_value = None

        agent_chain = MagicMock()
        agent_chain.filter_by.return_value.count.return_value = agent_count
        agent_chain.filter_by.return_value.first.return_value = existing_agent

        def route_query(model):
            model_name = getattr(model, "__name__", str(model))
            if "Allowlist" in model_name or "VerifierAllowlist" in str(model):
                return allowlist_chain
            if "Mbpolicy" in model_name or "VerifierMbpolicy" in str(model):
                return mbpolicy_chain
            return agent_chain

        mock_session.query.side_effect = route_query
        return mock_session

    def _run_post(self, session_mock):
        """Wire up validate_input and session_context, invoke handler.post()."""
        handler = _make_agents_handler(self.AGENT_ID)

        validate_return = ({"agents": self.AGENT_ID, "api_version": "2.1"}, self.AGENT_ID)
        handler.request.body = cloud_verifier_tornado.json.dumps(self.FULL_JSON_BODY).encode()

        @contextmanager
        def fake_session_ctx():
            yield session_mock

        with (
            patch.object(
                cloud_verifier_tornado.AgentsHandler,
                "_AgentsHandler__validate_input",
                return_value=validate_return,
            ),
            patch("keylime.cloud_verifier_tornado.session_context", fake_session_ctx),
            patch("keylime.cloud_verifier_tornado.web_util.echo_json_response") as mock_echo,
            patch("keylime.cloud_verifier_tornado.config.get", return_value="pull"),
            patch("keylime.cloud_verifier_tornado.config.getboolean", return_value=False),
            patch("keylime.cloud_verifier_tornado.ima.EMPTY_RUNTIME_POLICY", {}),
            patch("keylime.cloud_verifier_tornado.signing.get_runtime_policy_keys", return_value=None),
            patch("keylime.cloud_verifier_tornado.ima.verify_runtime_policy"),
            patch(
                "keylime.cloud_verifier_tornado.ima.runtime_policy_db_contents",
                return_value={
                    "name": self.AGENT_ID,
                    "checksum": "abc123",
                    "ima_policy": "{}",
                    "tpm_policy": "{}",
                },
            ),
            patch(
                "keylime.cloud_verifier_tornado.mba.mb_policy_db_contents",
                return_value={"name": self.AGENT_ID, "mb_policy": ""},
            ),
            patch("keylime.cloud_verifier_tornado.keylime_api_version.is_supported_version", return_value=True),
            patch("asyncio.ensure_future"),
            patch("keylime.cloud_verifier_tornado.VerifierAllowlist", MagicMock()),
            patch("keylime.cloud_verifier_tornado.VerifierMbpolicy", MagicMock()),
            patch("keylime.cloud_verifier_tornado.VerfierMain", MagicMock()),
            patch("keylime.cloud_verifier_tornado.cloud_verifier_common.DEFAULT_VERIFIER_ID", "test-verifier-id"),
        ):
            handler.post()
            return mock_echo

    def test_post_returns_409_for_active_agent(self):
        """POST returns 409 when agent exists and is NOT terminated."""
        mock_agent = MagicMock()
        mock_agent.operational_state = states.GET_QUOTE
        mock_session = self._make_session_mock(agent_count=1, existing_agent=mock_agent)

        mock_echo = self._run_post(mock_session)

        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 409)

    def test_post_cleans_up_terminated_agent(self):
        """POST cleans up TERMINATED agent and does not return 409."""
        mock_agent = MagicMock()
        mock_agent.operational_state = states.TERMINATED
        mock_agent.enrollment_generation = 0
        mock_session = self._make_session_mock(agent_count=1, existing_agent=mock_agent)

        with (
            patch("keylime.cloud_verifier_tornado.verifier_db_delete_agent") as mock_delete,
            patch("keylime.cloud_verifier_tornado.clear_agent_policy_cache") as mock_clear_cache,
        ):
            mock_echo = self._run_post(mock_session)

        mock_clear_cache.assert_called_once_with(self.AGENT_ID)
        mock_delete.assert_called_once_with(mock_session, self.AGENT_ID)

        # Verify successful enrollment (HTTP 200)
        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 200, "POST should return 200 for successful re-enrollment after TERMINATED cleanup")

        # Verify agent was added to session
        mock_session.add.assert_called()
        mock_session.commit.assert_called()

    def test_post_updates_auto_named_ima_policy_in_place(self):
        """POST updates auto-named IMA policy in-place when content differs."""
        # Mock existing IMA policy with a different checksum than what
        # runtime_policy_db_contents will return ("abc123")
        existing_policy = MagicMock()
        existing_policy.checksum = "old-checksum-123"
        existing_policy.ima_policy = "{}"
        existing_policy.tpm_policy = "{}"

        # _run_post patches VerifierAllowlist/VerifierMbpolicy with MagicMock(),
        # so route_query can't match by class name.  Use call-order tracking:
        # 1st query = VerfierMain (agent count check)
        # 2nd query = VerifierAllowlist (IMA policy lookup)
        # 3rd query = VerifierMbpolicy (MB policy lookup)
        # 4th+ queries = VerfierMain again (agent add via session.add, etc.)
        call_count = [0]

        agent_chain = MagicMock()
        agent_chain.filter_by.return_value.count.return_value = 0
        agent_chain.filter_by.return_value.first.return_value = None

        allowlist_chain = MagicMock()
        allowlist_chain.filter_by.return_value.one_or_none.return_value = existing_policy

        mbpolicy_chain = MagicMock()
        mbpolicy_chain.filter_by.return_value.one_or_none.return_value = None

        def route_query(_model):
            call_count[0] += 1
            if call_count[0] == 1:
                return agent_chain
            if call_count[0] == 2:
                return allowlist_chain
            if call_count[0] == 3:
                return mbpolicy_chain
            return agent_chain

        mock_session = MagicMock()
        mock_session.query.side_effect = route_query

        mock_echo = self._run_post(mock_session)

        # Verify HTTP 200 (successful enrollment)
        mock_echo.assert_called_once()
        args = mock_echo.call_args[0]
        self.assertEqual(args[1], 200, "POST should return 200 when updating auto-named policy in-place")

        # Verify policy attributes were updated in-place with new values
        # (from the mocked runtime_policy_db_contents return: checksum="abc123")
        self.assertEqual(existing_policy.checksum, "abc123")
        self.assertEqual(existing_policy.ima_policy, "{}")
        self.assertEqual(existing_policy.tpm_policy, "{}")
        mock_session.commit.assert_called()


class TestVerifierDbDeleteAgentPreservesSharedPolicies(unittest.TestCase):
    """Verify verifier_db_delete_agent preserves policies referenced by other agents."""

    AGENT_ID = "agent-aaa"

    def _make_session(self, allowlist_id=None, mbpolicy_id=None, other_agent_refs_ima=False, other_agent_refs_mb=False):
        """Build a mock session that routes query() calls by model."""
        session = MagicMock()

        # Track delete calls per model
        delete_tracker = {}

        def route_query(model):
            if "Allowlist" in str(model):
                chain = MagicMock()
                filter_chain = MagicMock()
                chain.filter_by.return_value = filter_chain
                if allowlist_id is not None:
                    row_mock = MagicMock()
                    row_mock.id = allowlist_id
                    filter_chain.first.return_value = row_mock
                else:
                    filter_chain.first.return_value = None
                filter_chain.delete.return_value = 0
                delete_tracker["allowlist"] = filter_chain.delete
                return chain
            if "Mbpolicy" in str(model):
                chain = MagicMock()
                filter_chain = MagicMock()
                chain.filter_by.return_value = filter_chain
                if mbpolicy_id is not None:
                    row_mock = MagicMock()
                    row_mock.id = mbpolicy_id
                    filter_chain.first.return_value = row_mock
                else:
                    filter_chain.first.return_value = None
                filter_chain.delete.return_value = 0
                delete_tracker["mbpolicy"] = filter_chain.delete
                return chain
            if "agent_id" in str(model):
                chain = MagicMock()
                filter_chain = MagicMock()
                chain.filter_by.return_value = filter_chain
                if other_agent_refs_ima or other_agent_refs_mb:
                    filter_chain.first.return_value = MagicMock()
                else:
                    filter_chain.first.return_value = None
                return chain
            chain = MagicMock()
            chain.filter_by.return_value.delete.return_value = 0
            return chain

        session.query.side_effect = route_query
        return session, delete_tracker

    @patch("keylime.cloud_verifier_tornado.Attestation")
    @patch("keylime.cloud_verifier_tornado.EvidenceItem")
    @patch("keylime.cloud_verifier_tornado.get_AgentAttestStates")
    @patch("keylime.cloud_verifier_tornado.push_agent_monitor")
    def test_deletes_policy_when_no_other_agent_references_it(self, _mock_push, _mock_aas, _mock_ev, _mock_att):
        """Auto-named policy is deleted when no other agent references it."""
        session, tracker = self._make_session(allowlist_id=42, other_agent_refs_ima=False)

        cloud_verifier_tornado.verifier_db_delete_agent(session, self.AGENT_ID)

        self.assertIn("allowlist", tracker)
        tracker["allowlist"].assert_called_once()

    @patch("keylime.cloud_verifier_tornado.Attestation")
    @patch("keylime.cloud_verifier_tornado.EvidenceItem")
    @patch("keylime.cloud_verifier_tornado.get_AgentAttestStates")
    @patch("keylime.cloud_verifier_tornado.push_agent_monitor")
    def test_preserves_policy_when_another_agent_references_it(self, _mock_push, _mock_aas, _mock_ev, _mock_att):
        """Auto-named policy is NOT deleted when another agent references it."""
        session, tracker = self._make_session(allowlist_id=42, other_agent_refs_ima=True)

        cloud_verifier_tornado.verifier_db_delete_agent(session, self.AGENT_ID)

        tracker["allowlist"].assert_not_called()

    @patch("keylime.cloud_verifier_tornado.Attestation")
    @patch("keylime.cloud_verifier_tornado.EvidenceItem")
    @patch("keylime.cloud_verifier_tornado.get_AgentAttestStates")
    @patch("keylime.cloud_verifier_tornado.push_agent_monitor")
    def test_skips_policy_when_no_auto_named_policy_exists(self, _mock_push, _mock_aas, _mock_ev, _mock_att):
        """No error when the agent has no auto-named policy."""
        session, tracker = self._make_session(allowlist_id=None, mbpolicy_id=None)

        cloud_verifier_tornado.verifier_db_delete_agent(session, self.AGENT_ID)

        tracker["allowlist"].assert_not_called()
        tracker["mbpolicy"].assert_not_called()
        session.commit.assert_called_once()

    @patch("keylime.cloud_verifier_tornado.Attestation")
    @patch("keylime.cloud_verifier_tornado.EvidenceItem")
    @patch("keylime.cloud_verifier_tornado.get_AgentAttestStates")
    @patch("keylime.cloud_verifier_tornado.push_agent_monitor")
    def test_skips_cleanup_when_generation_mismatches(self, _mock_push, _mock_aas, _mock_ev, _mock_att):
        """verifier_db_delete_agent returns early when expected_generation doesn't match."""
        session = MagicMock()

        # Mock the .first() query for enrollment_generation — returns (10,) (mismatches expected 5)
        gen_chain = MagicMock()
        gen_chain.filter_by.return_value.first.return_value = (10,)

        def route_query(model):
            # VerfierMain.enrollment_generation is a column attribute
            if "enrollment_generation" in str(model) or "VerfierMain" in str(model):
                return gen_chain
            chain = MagicMock()
            chain.filter_by.return_value.first.return_value = None
            return chain

        session.query.side_effect = route_query

        # Call with expected_generation=5 (which doesn't match current gen=10)
        cloud_verifier_tornado.verifier_db_delete_agent(session, self.AGENT_ID, expected_generation=5)

        # Verify generation was checked
        gen_chain.filter_by.assert_called_once_with(agent_id=self.AGENT_ID)
        gen_chain.filter_by.return_value.first.assert_called_once()

        # Verify early return — no evidence/attestation deletion, no commit
        _mock_ev.delete_all.assert_not_called()
        _mock_att.delete_all.assert_not_called()
        session.commit.assert_not_called()


class TestProcessAgentGenerationGuard(unittest.TestCase):
    """Verify process_agent stops polling when generation filter matches 0 rows."""

    @patch("keylime.cloud_verifier_tornado._complete_deletion_if_terminated")
    @patch("keylime.cloud_verifier_tornado._cancel_pending_event")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_stops_polling_when_update_matches_zero_rows_due_to_stale_generation(
        self, mock_session_ctx, _mock_cancel, mock_complete_deletion
    ):
        """process_agent stops polling when UPDATE with generation filter matches 0 rows."""
        # Create agent dict with enrollment_generation
        agent = {
            "agent_id": "test-agent-123",
            "operational_state": states.GET_QUOTE,
            "enrollment_generation": 1,
        }

        # Create mock stored_agent
        mock_stored_agent = MagicMock()
        mock_stored_agent.operational_state = states.GET_QUOTE
        mock_stored_agent.enrollment_generation = 1
        mock_stored_agent.mb_policy = None

        # Mock session for initial read
        mock_read_session = MagicMock()
        mock_query_chain = MagicMock()
        mock_query_chain.options.return_value = mock_query_chain
        mock_query_chain.filter_by.return_value = mock_query_chain
        mock_query_chain.first.return_value = mock_stored_agent
        mock_read_session.query.return_value = mock_query_chain

        # Mock session for UPDATE (returns 0 rows)
        mock_update_session = MagicMock()
        mock_update_chain = MagicMock()
        mock_update_chain.filter_by.return_value = mock_update_chain
        mock_update_chain.filter.return_value = mock_update_chain
        mock_update_chain.update.return_value = 0  # No rows updated (stale generation)
        mock_update_session.query.return_value = mock_update_chain

        # session_context yields read session first, then update session
        sessions = [mock_read_session, mock_update_session]
        session_idx = [0]

        @contextmanager
        def fake_session_ctx():
            yield sessions[session_idx[0]]
            session_idx[0] += 1

        mock_session_ctx.side_effect = fake_session_ctx

        asyncio.run(cloud_verifier_tornado.process_agent(agent, states.GET_QUOTE))

        # Verify _complete_deletion_if_terminated was called (stops polling)
        mock_complete_deletion.assert_called_once_with("test-agent-123")

    @patch("keylime.cloud_verifier_tornado._complete_deletion_if_terminated")
    @patch("keylime.cloud_verifier_tornado._cancel_pending_event")
    @patch("keylime.cloud_verifier_tornado.session_context")
    def test_stops_stale_coroutine_when_db_has_newer_generation(
        self, mock_session_ctx, mock_cancel, _mock_complete_deletion
    ):
        """process_agent stops a stale coroutine whose generation is behind the DB row."""
        # Stale agent dict has generation 0
        agent = {
            "agent_id": "test-agent-456",
            "operational_state": states.GET_QUOTE,
            "enrollment_generation": 0,
        }

        # DB row has generation 1 (replacement enrollment)
        mock_stored_agent = MagicMock()
        mock_stored_agent.operational_state = states.GET_QUOTE
        mock_stored_agent.enrollment_generation = 1
        mock_stored_agent.mb_policy = None

        mock_read_session = MagicMock()
        mock_query_chain = MagicMock()
        mock_query_chain.options.return_value = mock_query_chain
        mock_query_chain.filter_by.return_value = mock_query_chain
        mock_query_chain.first.return_value = mock_stored_agent
        mock_read_session.query.return_value = mock_query_chain

        @contextmanager
        def fake_session_ctx():
            yield mock_read_session

        mock_session_ctx.side_effect = fake_session_ctx

        asyncio.run(cloud_verifier_tornado.process_agent(agent, states.GET_QUOTE))

        # Stale coroutine should stop — cancel pending event, no UPDATE attempted
        mock_cancel.assert_called_once_with(agent)
        # No update session was needed — the coroutine returned early
        _mock_complete_deletion.assert_not_called()


if __name__ == "__main__":
    unittest.main()
