import asyncio
from typing import List, Optional

import tornado.httpserver
import tornado.ioloop
import tornado.process
from sqlalchemy.exc import SQLAlchemyError

from keylime import cloud_verifier_common, cloud_verifier_tornado, config, keylime_logging
from keylime.common import states
from keylime.db.keylime_db import SessionManager, make_engine
from keylime.db.verifier_db import VerfierMain
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
        self._worker_agents: Optional[List[VerfierMain]] = None

    def start_multi(self) -> None:  # pylint: disable=no-member
        """Override to support PULL mode agent activation across multiple workers."""
        # Get all agents from database before forking (only needed for PULL mode)
        logger.info("start_multi() called with operating_mode: %s", self.operating_mode)
        all_agents: List[VerfierMain] = []
        if self.operating_mode == "pull":
            verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
            logger.info("Querying agents for verifier_id: %s", verifier_id)
            all_agents = cloud_verifier_tornado.get_agents_by_verifier_id(verifier_id)
            logger.info("Found %d agents in database before forking", len(all_agents))

        # Log server startup (copied from base class)
        ports = ""
        protocols = ""
        if self._Server__tornado_http_sockets:  # type: ignore # pylint: disable=no-member
            ports = str(self.http_port)
            protocols = "HTTP"
        if self._Server__tornado_https_sockets and self.ssl_ctx:  # type: ignore # pylint: disable=no-member
            ports = f"{ports}/{self.https_port}" if ports else f"{self.https_port}"
            protocols = f"{protocols}/S" if protocols else "HTTPS"
        logger.info(
            "Listening on %s:%s (%s) with %s worker processes...",
            self.bind_interface,
            ports,
            protocols,
            self.worker_count,
        )

        # Fork worker processes - returns task_id in each child process
        task_id = tornado.process.fork_processes(self.worker_count)

        # CRITICAL: Reset any database state inherited from parent process.
        # The parent initializes globals when querying agents (line 39), so children
        # inherit initialized state. We must reset to trigger lazy re-initialization.
        cloud_verifier_tornado.reset_verifier_config()

        # Distribute agents to this worker using round-robin (task_id is the worker index)
        if self.operating_mode == "pull" and all_agents:
            self._worker_agents = [all_agents[i] for i in range(task_id, len(all_agents), self.worker_count)]
            logger.info("Worker %d assigned %d agent(s)", task_id, len(self._worker_agents))

        # Start this worker's HTTP/HTTPS servers and activate agents
        self.start_single()

    def start_single(self) -> None:  # type: ignore[override]  # pylint: disable=attribute-defined-outside-init,invalid-overridden-method
        """Override to support PULL mode agent activation after server startup."""
        # Start HTTP/HTTPS servers (logic copied from parent to allow agent activation before blocking)
        # pylint: disable=no-member
        if self._Server__tornado_http_sockets:  # type: ignore
            http_server = tornado.httpserver.HTTPServer(
                self._Server__tornado_app, ssl_options=None, max_buffer_size=self.max_upload_size  # type: ignore
            )
            http_server.add_sockets(self._Server__tornado_http_sockets)  # type: ignore
            self._Server__tornado_http_server = http_server  # type: ignore # pylint: disable=attribute-defined-outside-init

        if self._Server__tornado_https_sockets and self.ssl_ctx:  # type: ignore
            https_server = tornado.httpserver.HTTPServer(
                self._Server__tornado_app, ssl_options=self.ssl_ctx, max_buffer_size=self.max_upload_size  # type: ignore
            )
            https_server.add_sockets(self._Server__tornado_https_sockets)  # type: ignore
            self._Server__tornado_https_server = https_server  # type: ignore # pylint: disable=attribute-defined-outside-init
        # pylint: enable=no-member

        # Activate agents for PULL mode
        if self.operating_mode == "pull" and self._worker_agents:
            verifier_host = config.get("verifier", "ip")
            verifier_port = config.get("verifier", "port")
            logger.info("Activating %d agent(s) for PULL mode", len(self._worker_agents))
            asyncio.ensure_future(
                cloud_verifier_tornado.activate_agents(self._worker_agents, verifier_host, int(verifier_port))
            )

        # Wait forever (until event loop is stopped)
        tornado.ioloop.IOLoop.current().start()

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

    def _setup(self) -> None:
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
        self._get("/", ServerInfoController, "show_root")
        self._get("/versions", ServerInfoController, "show_versions")
        self._get("/version", ServerInfoController, "show_versions")

    @Server.version_scope(2)
    def _v2_routes(self) -> None:
        self._get("/", ServerInfoController, "show_version_root")

        # Routes for managing agent resources
        self._agent_routes()
        # Agent management routes which are replaced in API v3
        self._v2_agent_routes()
        # Routes for managing measured boot verification in API v2
        self._v2_mb_routes()
        # Routes for managing IMA verification in API v2
        self._v2_ima_routes()
        # Routes for on-demand identity verification in API v2 (public)
        self._v2_identity_routes()
        # Routes for on-demand evidence verification in API v2 (public)
        self._v2_evidence_routes()

        # Note: push-specific endpoints are only available from API v3 onwards

    @Server.version_scope(3)
    def _v3_routes(self) -> None:
        self._get("/", ServerInfoController, "show_version_root")

        # Routes for managing agent resources
        self._agent_routes()
        # Agent management routes available from API v3
        self._v3_agent_routes()
        # Routes for managing push attestation resources (API v3+ only)
        self._attestation_routes()
        # Routes for managing measured boot verification in API v3+
        self._v3_mb_routes()
        # Routes for managing IMA verification in API v3+
        self._v3_ima_routes()
        # Routes for on-demand verification of evidence in API v3+
        self._v3_evidence_routes()
        # Routes for agent athentication
        self._v3_authentication_routes()

    def _agent_routes(self) -> None:
        # Routes used to manage agents enrolled for verification
        self._get("/agents", AgentController, "index")
        self._get("/agents/:agent_id", AgentController, "show")
        self._delete("/agents/:agent_id", AgentController, "delete")

    def _v2_agent_routes(self) -> None:
        # Routes used to manage agents enrolled for verification
        self._post("/agents/:agent_id", AgentController, "create")

        # Routes used in pull mode to control polling for attestations from agents
        self._put("/agents/:agent_id/reactivate", AgentController, "reactivate")
        self._put("/agents/:agent_id/stop", AgentController, "stop")
        # Note: in v3+, these actions are performed by mutating agent resources directly

    def _v3_agent_routes(self) -> None:
        # Routes used to manage agents enrolled for verification (which adhere to RFC 9110 semantics)
        self._post("/agents", AgentController, "create")
        self._patch("/agents/:agent_id", AgentController, "update")
        # Note: in pull mode, the update action includes turning polling on/off

    @Server.push_only
    def _attestation_routes(self) -> None:
        # Routes for managing push attestation resources
        # Note: These routes must use HTTPS to protect sensitive TPM quotes and attestation evidence in transit.
        self._get("/agents/:agent_id/attestations", AttestationController, "index")
        self._post("/agents/:agent_id/attestations", AttestationController, "create")
        self._get("/agents/:agent_id/attestations/latest", AttestationController, "show_latest")
        self._patch("/agents/:agent_id/attestations/latest", AttestationController, "update_latest")
        self._get("/agents/:agent_id/attestations/:index", AttestationController, "show")
        self._patch("/agents/:agent_id/attestations/:index", AttestationController, "update")

    def _v2_mb_routes(self) -> None:
        # Routes used to manage reference states for MB/UEFI verification
        self._get("/mbpolicies", MBRefStateController, "index")
        self._post("/mbpolicies/:name", MBRefStateController, "create")
        self._get("/mbpolicies/:name", MBRefStateController, "show")
        self._put("/mbpolicies/:name", MBRefStateController, "overwrite")
        self._delete("/mbpolicies/:name", MBRefStateController, "delete")

    def _v3_mb_routes(self) -> None:
        # Routes used to manage reference states for MB/UEFI verification (which adhere to RFC 9110 semantics)
        self._get("/refstates/uefi", MBRefStateController, "index")
        self._post("/refstates/uefi", MBRefStateController, "create")
        self._get("/refstates/uefi/:name", MBRefStateController, "show")
        self._patch("/refstates/uefi/:name", MBRefStateController, "update")
        self._delete("/refstates/uefi/:name", MBRefStateController, "delete")

    def _v2_ima_routes(self) -> None:
        # Routes used to manage policies for IMA verification
        self._get("/allowlists", IMAPolicyController, "index")
        self._get("/allowlists/:name", IMAPolicyController, "show")
        self._post("/allowlists/:name", IMAPolicyController, "create")
        self._put("/allowlists/:name", IMAPolicyController, "overwrite")
        self._delete("/allowlists/:name", IMAPolicyController, "delete")

    def _v3_ima_routes(self) -> None:
        # Routes used to manage policies for IMA verification (which adhere to RFC 9110 semantics)
        self._get("/policies/ima", IMAPolicyController, "index")
        self._get("/policies/ima/:name", IMAPolicyController, "show")
        self._post("/policies/ima", IMAPolicyController, "create")
        self._patch("/policies/ima/:name", IMAPolicyController, "update")
        self._delete("/policies/ima/:name", IMAPolicyController, "delete")

    def _v2_identity_routes(self) -> None:
        # Routes for on-demand identity verification (public - allows third-party verification)
        self._get("/verify/identity", IdentityController, "verify")  # Public: VERIFY_IDENTITY

    def _v2_evidence_routes(self) -> None:
        # Routes for on-demand evidence verification in v2 (public - allows third-party verification)
        self._post("/verify/evidence", EvidenceController, "process")  # Public: VERIFY_EVIDENCE

    def _v3_evidence_routes(self) -> None:
        # Routes for on-demand verification of evidence in v3+ (public - allows third-party verification)
        self._post("/verify/evidence", EvidenceController, "process")  # Public: VERIFY_EVIDENCE

    def _v3_authentication_routes(self) -> None:
        # Routes for agent authentication
        # Note: These routes must use HTTPS to protect challenges and authentication tokens in transit.
        # While the authentication protocol uses TPM proof of possession instead of mTLS certificates,
        # TLS encryption is still required to prevent interception and replay attacks.
        self._post("/sessions", SessionController, "create_session")
        self._patch("/sessions/:session_id", SessionController, "update_session")
        self._get("/agents/:agent_id/session/:token", SessionController, "show")
        self._post("/agents/:agent_id/session", SessionController, "create")
        self._patch("/agents/:agent_id/session/:token", SessionController, "update")
