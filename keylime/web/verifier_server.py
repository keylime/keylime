import asyncio
from typing import List, Optional

from sqlalchemy.exc import SQLAlchemyError

from keylime import (
    cloud_verifier_common,
    cloud_verifier_tornado,
    config,
    keylime_logging,
    push_agent_monitor,
    revocation_notifier,
)
from keylime.authorization.provider import Action
from keylime.common import states
from keylime.db.keylime_db import SessionManager, make_engine
from keylime.db.verifier_db import VerfierMain
from keylime.models.verifier.auth_session import AuthSession
from keylime.web.base.server import Server
from keylime.web.verifier.agent_controller import AgentController
from keylime.web.verifier.attestation_controller import AttestationController
from keylime.web.verifier.evidence_controller import EvidenceController
from keylime.web.verifier.identity_controller import IdentityController
from keylime.web.verifier.ima_policy_controller import IMAPolicyController
from keylime.web.verifier.mb_ref_state_controller import MBRefStateController
from keylime.web.verifier.server_info_controller import ServerInfoController
from keylime.web.verifier.session_controller import SessionController

logger = keylime_logging.init_logging("verifier")


class VerifierServer(Server):
    def __init__(self) -> None:
        super().__init__()
        self._prepare_agents_on_startup()
        self._clear_stale_sessions_on_startup()
        self._all_agents: List[VerfierMain] = []
        self._worker_agents: Optional[List[VerfierMain]] = None
        self._activate_task: Optional[asyncio.Task[None]] = None

    def _pre_fork(self) -> None:
        """Query agents from database before forking (only needed for PULL mode)."""
        logger.info("start_multi() called with operating_mode: %s", self.operating_mode)
        self._all_agents = []
        if self.operating_mode == "pull":
            verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
            logger.info("Querying agents for verifier_id: %s", verifier_id)
            self._all_agents = cloud_verifier_tornado.get_agents_by_verifier_id(verifier_id)
            logger.info("Found %d agents in database before forking", len(self._all_agents))

    def _post_fork(self, task_id: int) -> None:
        """Reset inherited DB state and distribute agents to this worker."""
        # CRITICAL: Reset any database state inherited from parent process.
        # The parent initializes globals when querying agents in _pre_fork(),
        # so children inherit initialized state. We must reset to trigger
        # lazy re-initialization.
        cloud_verifier_tornado.reset_verifier_config()

        # Distribute agents to this worker using round-robin (task_id is the worker index)
        if self.operating_mode == "pull" and self._all_agents:
            self._worker_agents = [
                self._all_agents[i] for i in range(task_id, len(self._all_agents), self.worker_count)
            ]
            logger.info("Worker %d assigned %d agent(s)", task_id, len(self._worker_agents))

    async def _on_server_started(self) -> None:
        """Activate agents for PULL mode after servers are listening."""
        # In start_single() mode (single-process), _pre_fork/_post_fork
        # are never called so _worker_agents is None and _all_agents is
        # empty.  Query agents directly in that case.
        agents = self._worker_agents if self._worker_agents is not None else self._all_agents
        if self.operating_mode == "pull" and not agents and self._worker_agents is None:
            verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
            agents = cloud_verifier_tornado.get_agents_by_verifier_id(verifier_id)
        if self.operating_mode == "pull" and agents:
            verifier_host = config.get("verifier", "ip")
            verifier_port = config.get("verifier", "port")
            logger.info("Activating %d agent(s) for PULL mode", len(agents))
            self._activate_task = asyncio.ensure_future(
                cloud_verifier_tornado.activate_agents(agents, verifier_host, int(verifier_port))
            )

    async def _graceful_shutdown(self) -> None:
        """Cancel attestation-specific pending work and drain in-flight operations before stopping servers."""
        # Cancel all pending attestation timeouts (retries, polls)
        cloud_verifier_tornado.cancel_all_pending_events()
        push_agent_monitor.cancel_all_timeouts()

        # Wait for in-flight attestation operations to complete before
        # tearing down webhook workers — in-flight process_agent() calls
        # may still need to send revocation notifications.
        drain_timeout = config.getfloat("verifier", "shutdown_drain_timeout", fallback=10.0)
        drained = await cloud_verifier_tornado.wait_for_drain(drain_timeout)
        if not drained:
            logger.warning(
                "Shutting down with %d attestation operation(s) still active after %.1fs",
                cloud_verifier_tornado.get_active_operations(),
                drain_timeout,
            )

        # Shutdown webhook workers after draining so revocation
        # notifications from in-flight attestations are delivered.
        if "webhook" in revocation_notifier.get_notifiers():
            revocation_notifier.shutdown_webhook_workers()

        await super()._graceful_shutdown()

    def _prepare_agents_on_startup(self) -> None:
        """Prepare agents in database for verifier startup.

        This method resets agents in reactivate states to START so activate_agents()
        can restart their polling loops. This matches the old architecture behavior.

        IMPORTANT: This runs in the parent process before forking. We create a
        temporary engine and dispose it immediately to avoid leaking connections
        to child worker processes.
        """
        # Create a temporary engine/session for this one-time initialization
        # This matches the old cloud_verifier_tornado.py pattern (lines 2371-2386)
        engine = make_engine("cloud_verifier")
        session_manager = SessionManager()

        try:
            with session_manager.session_context(engine) as session:
                try:
                    # Reset agents in APPROVED_REACTIVATE_STATES to START state
                    # This matches the old architecture (cloud_verifier_tornado.py:2332-2338)
                    query_all = session.query(VerfierMain).all()
                    for row in query_all:
                        if row.operational_state in states.APPROVED_REACTIVATE_STATES:
                            row.operational_state = states.START  # type: ignore

                    # Log remaining agents
                    num = session.query(VerfierMain).count()
                    if num > 0:
                        agent_ids = [row[0] for row in session.query(VerfierMain.agent_id).all()]
                        logger.info("Agent ids in db loaded from file: %s", agent_ids)

                except SQLAlchemyError as e:
                    logger.error("Error preparing agents on startup: %s", e)
                    raise
        finally:
            # Dispose the engine to close all connections before forking
            # This prevents child processes from inheriting invalid connections
            # Matches cloud_verifier_tornado.py:2411 (engine.dispose() after fork)
            engine.dispose()

    def _clear_stale_sessions_on_startup(self) -> None:
        """Clear expired authentication sessions from database on verifier startup.

        This cleans up expired sessions that accumulated while the verifier was down.
        Valid sessions are preserved in the database and will be restored to shared
        memory when agents use them, allowing agents to continue using valid tokens
        after a verifier restart without re-authentication.
        """
        try:
            AuthSession.clear_expired_sessions_on_startup()
        except Exception as e:
            logger.error("Error clearing expired sessions on startup: %s", e)
            # Don't fail startup, but log the error

    def _setup(self) -> None:
        self._set_component("verifier")
        self._use_config("verifier")
        self._set_operating_mode(from_config="mode", fallback="pull")
        self._set_bind_interface(from_config="ip")
        self._set_http_port(value=None)  # verifier does not accept insecure connections
        self._set_https_port(from_config="port")
        self._set_max_upload_size(from_config="max_upload_size")
        self._set_default_ssl_ctx()

    def _routes(self) -> None:
        self._top_level_routes()
        self._v2_routes()
        self._v3_routes()

    def _top_level_routes(self) -> None:
        # Public routes - no authentication required
        self._get("/", ServerInfoController, "show_root", auth_action=Action.READ_SERVER_INFO)
        self._get("/versions", ServerInfoController, "show_versions", auth_action=Action.READ_VERSION)
        self._get("/version", ServerInfoController, "show_versions", auth_action=Action.READ_VERSION)

    @Server.version_scope(2)
    def _v2_routes(self) -> None:
        # Public: version info
        self._get("/", ServerInfoController, "show_version_root", auth_action=Action.READ_SERVER_INFO)

        # Routes for managing agent resources (admin + agent-read-own)
        self._agent_routes()
        # Agent management routes which are replaced in API v3 (admin only)
        self._v2_agent_routes()
        # Routes for managing measured boot verification in API v2 (admin only)
        self._v2_mb_routes()
        # Routes for managing IMA verification in API v2 (admin only)
        self._v2_ima_routes()
        # Routes for on-demand identity verification in API v2 (public)
        self._v2_identity_routes()
        # Routes for on-demand evidence verification in API v2 (public)
        self._v2_evidence_routes()

        # Note: push-specific endpoints are only available from API v3 onwards

    @Server.version_scope(3)
    def _v3_routes(self) -> None:
        # Public: version info
        self._get("/", ServerInfoController, "show_version_root", auth_action=Action.READ_SERVER_INFO)

        # Routes for managing agent resources (admin + agent-read-own)
        self._agent_routes()
        # Agent management routes available from API v3 (admin only)
        self._v3_agent_routes()
        # Routes for managing push attestation resources (API v3+ only, agent + admin)
        self._attestation_routes()
        # Routes for managing measured boot verification in API v3+ (admin only)
        self._v3_mb_routes()
        # Routes for managing IMA verification in API v3+ (admin only)
        self._v3_ima_routes()
        # Routes for on-demand verification of evidence in API v3+ (public)
        self._v3_evidence_routes()
        # Routes for agent authentication (public - creates sessions)
        self._v3_authentication_routes()

    def _agent_routes(self) -> None:
        # Routes used to manage agents enrolled for verification
        # Admin: list all agents
        self._get("/agents", AgentController, "index", requires_auth=True, auth_action=Action.LIST_AGENTS)
        # Agent/Admin: read agent status (agent can read own, admin can read any)
        self._get("/agents/:agent_id", AgentController, "show", requires_auth=True, auth_action=Action.READ_AGENT)
        # Admin: delete agent
        self._delete(
            "/agents/:agent_id", AgentController, "delete", requires_auth=True, auth_action=Action.DELETE_AGENT
        )

    def _v2_agent_routes(self) -> None:
        # Routes used to manage agents enrolled for verification (admin only)
        self._post("/agents/:agent_id", AgentController, "create", requires_auth=True, auth_action=Action.CREATE_AGENT)

        # Routes used in pull mode to control polling for attestations from agents (admin only)
        self._put(
            "/agents/:agent_id/reactivate",
            AgentController,
            "reactivate",
            requires_auth=True,
            auth_action=Action.REACTIVATE_AGENT,
        )
        self._put("/agents/:agent_id/stop", AgentController, "stop", requires_auth=True, auth_action=Action.STOP_AGENT)
        # Note: in v3+, these actions are performed by mutating agent resources directly

    def _v3_agent_routes(self) -> None:
        # Routes used to manage agents enrolled for verification (admin only, RFC 9110 semantics)
        self._post("/agents", AgentController, "create", requires_auth=True, auth_action=Action.CREATE_AGENT)
        self._patch("/agents/:agent_id", AgentController, "update", requires_auth=True, auth_action=Action.UPDATE_AGENT)
        # Note: in pull mode, the update action includes turning polling on/off

    @Server.push_only
    def _attestation_routes(self) -> None:
        # Routes for managing push attestation resources
        # Note: These routes must use HTTPS to protect sensitive TPM quotes and attestation evidence in transit.
        # Admin: list/read attestations
        self._get(
            "/agents/:agent_id/attestations",
            AttestationController,
            "index",
            requires_auth=True,
            auth_action=Action.LIST_ATTESTATIONS,
        )
        self._get(
            "/agents/:agent_id/attestations/latest",
            AttestationController,
            "show_latest",
            requires_auth=True,
            auth_action=Action.READ_ATTESTATION,
        )
        self._get(
            "/agents/:agent_id/attestations/:index",
            AttestationController,
            "show",
            requires_auth=True,
            auth_action=Action.READ_ATTESTATION,
        )
        # Agent: submit attestations (agent can only submit for own agent_id)
        self._post(
            "/agents/:agent_id/attestations",
            AttestationController,
            "create",
            requires_auth=True,
            auth_action=Action.SUBMIT_ATTESTATION,
        )
        self._patch(
            "/agents/:agent_id/attestations/latest",
            AttestationController,
            "update_latest",
            requires_auth=True,
            auth_action=Action.SUBMIT_ATTESTATION,
        )
        self._patch(
            "/agents/:agent_id/attestations/:index",
            AttestationController,
            "update",
            requires_auth=True,
            auth_action=Action.SUBMIT_ATTESTATION,
        )

    def _v2_mb_routes(self) -> None:
        # Routes used to manage reference states for MB/UEFI verification (admin only)
        self._get("/mbpolicies", MBRefStateController, "index", requires_auth=True, auth_action=Action.LIST_MB_POLICIES)
        self._post(
            "/mbpolicies/:name", MBRefStateController, "create", requires_auth=True, auth_action=Action.CREATE_MB_POLICY
        )
        self._get(
            "/mbpolicies/:name", MBRefStateController, "show", requires_auth=True, auth_action=Action.READ_MB_POLICY
        )
        self._put(
            "/mbpolicies/:name",
            MBRefStateController,
            "overwrite",
            requires_auth=True,
            auth_action=Action.UPDATE_MB_POLICY,
        )
        self._delete(
            "/mbpolicies/:name", MBRefStateController, "delete", requires_auth=True, auth_action=Action.DELETE_MB_POLICY
        )

    def _v3_mb_routes(self) -> None:
        # Routes used to manage reference states for MB/UEFI verification (admin only, RFC 9110 semantics)
        self._get(
            "/refstates/uefi", MBRefStateController, "index", requires_auth=True, auth_action=Action.LIST_MB_POLICIES
        )
        self._post(
            "/refstates/uefi", MBRefStateController, "create", requires_auth=True, auth_action=Action.CREATE_MB_POLICY
        )
        self._get(
            "/refstates/uefi/:name", MBRefStateController, "show", requires_auth=True, auth_action=Action.READ_MB_POLICY
        )
        self._patch(
            "/refstates/uefi/:name",
            MBRefStateController,
            "update",
            requires_auth=True,
            auth_action=Action.UPDATE_MB_POLICY,
        )
        self._delete(
            "/refstates/uefi/:name",
            MBRefStateController,
            "delete",
            requires_auth=True,
            auth_action=Action.DELETE_MB_POLICY,
        )

    def _v2_ima_routes(self) -> None:
        # Routes used to manage policies for IMA verification (admin only)
        self._get(
            "/allowlists", IMAPolicyController, "index", requires_auth=True, auth_action=Action.LIST_RUNTIME_POLICIES
        )
        self._get(
            "/allowlists/:name", IMAPolicyController, "show", requires_auth=True, auth_action=Action.READ_RUNTIME_POLICY
        )
        self._post(
            "/allowlists/:name",
            IMAPolicyController,
            "create",
            requires_auth=True,
            auth_action=Action.CREATE_RUNTIME_POLICY,
        )
        self._put(
            "/allowlists/:name",
            IMAPolicyController,
            "overwrite",
            requires_auth=True,
            auth_action=Action.UPDATE_RUNTIME_POLICY,
        )
        self._delete(
            "/allowlists/:name",
            IMAPolicyController,
            "delete",
            requires_auth=True,
            auth_action=Action.DELETE_RUNTIME_POLICY,
        )

    def _v3_ima_routes(self) -> None:
        # Routes used to manage policies for IMA verification (admin only, RFC 9110 semantics)
        self._get(
            "/policies/ima", IMAPolicyController, "index", requires_auth=True, auth_action=Action.LIST_RUNTIME_POLICIES
        )
        self._get(
            "/policies/ima/:name",
            IMAPolicyController,
            "show",
            requires_auth=True,
            auth_action=Action.READ_RUNTIME_POLICY,
        )
        self._post(
            "/policies/ima", IMAPolicyController, "create", requires_auth=True, auth_action=Action.CREATE_RUNTIME_POLICY
        )
        self._patch(
            "/policies/ima/:name",
            IMAPolicyController,
            "update",
            requires_auth=True,
            auth_action=Action.UPDATE_RUNTIME_POLICY,
        )
        self._delete(
            "/policies/ima/:name",
            IMAPolicyController,
            "delete",
            requires_auth=True,
            auth_action=Action.DELETE_RUNTIME_POLICY,
        )

    def _v2_identity_routes(self) -> None:
        # Routes for on-demand identity verification (public - allows third-party verification)
        self._get("/verify/identity", IdentityController, "verify", auth_action=Action.VERIFY_IDENTITY)

    def _v2_evidence_routes(self) -> None:
        # Routes for on-demand evidence verification in v2 (public - allows third-party verification)
        self._post("/verify/evidence", EvidenceController, "process", auth_action=Action.VERIFY_EVIDENCE)

    def _v3_evidence_routes(self) -> None:
        # Routes for on-demand verification of evidence in v3+ (public - allows third-party verification)
        self._post("/verify/evidence", EvidenceController, "process", auth_action=Action.VERIFY_EVIDENCE)

    def _v3_authentication_routes(self) -> None:
        # Routes for agent authentication
        # Note: These routes must use HTTPS to protect challenges and authentication tokens in transit.
        # While the authentication protocol uses TPM proof of possession instead of mTLS certificates,
        # TLS encryption is still required to prevent interception and replay attacks.

        # Public: session creation (agent initiates authentication with TPM PoP)
        self._post("/sessions", SessionController, "create_session", auth_action=Action.CREATE_SESSION)
        # Public: session update handles both initial PoP completion (anonymous) and token extension
        # The session controller validates the PoP response or existing token internally
        self._patch("/sessions/:session_id", SessionController, "update_session", auth_action=Action.EXTEND_SESSION)

        # Legacy session routes (kept for backwards compatibility)
        # These routes pass the token in the URL path; the session controller validates it internally
        self._get("/agents/:agent_id/session/:token", SessionController, "show", auth_action=Action.EXTEND_SESSION)
        self._post("/agents/:agent_id/session", SessionController, "create", auth_action=Action.CREATE_SESSION)
        self._patch("/agents/:agent_id/session/:token", SessionController, "update", auth_action=Action.EXTEND_SESSION)
