import base64

from sqlalchemy.orm import Session

from keylime import config, keylime_logging
from keylime.db.keylime_db import SessionManager, make_engine
from keylime.db.verifier_db import VerfierMain
from keylime.models.base import Timestamp
from keylime.models.verifier import AuthSession
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")

# GLOBAL_POLICY_CACHE: Dict[str, Dict[str, str]] = {}

_engine = None


def get_session() -> Session:
    global _engine
    if _engine is None:
        _engine = make_engine("cloud_verifier")
    return SessionManager().make_session(_engine)


class SessionController(Controller):
    # POST /v3[.:minor]/sessions
    def create_session(self, **params):
        """Create a new authentication session.

        This endpoint ALWAYS succeeds unless the request is malformed or rate limited.
        The session is stored in shared memory (not database) until PoP is verified.
        Agent existence is checked during the PATCH (proof submission) step.
        """
        from keylime.models.verifier.rate_limiter import RateLimiter  # pylint: disable=import-outside-toplevel

        # Check IP-based rate limit to prevent broad DoS attacks
        # Default allows for multiple agents from same IP (testing, NAT, etc.)
        client_ip = self.action_handler.request.remote_ip
        ip_rate_limit = config.getint("verifier", "session_create_rate_limit_per_ip", fallback=50)
        ip_rate_window = config.getint("verifier", "session_create_rate_limit_window_ip", fallback=60)

        allowed, retry_after = RateLimiter.check_rate_limit(
            f"ip:{client_ip}", max_requests=ip_rate_limit, window_seconds=ip_rate_window
        )
        if not allowed:
            error_body = {
                "errors": [
                    {
                        "status": "429",
                        "title": "Too Many Requests",
                        "detail": "Rate limit exceeded. Please try again later.",
                    }
                ]
            }
            self.action_handler.set_header("Retry-After", str(retry_after))
            self.send_response(code=429, body=error_body)
            return

        # Extract agent_id from request body
        data = params.get("data", {})
        attributes = data.get("attributes", {})
        agent_id = attributes.get("agent_id")

        if not agent_id:
            error_body = {"errors": [{"status": "400", "title": "Bad Request", "detail": "agent_id is required"}]}
            self.send_response(code=400, body=error_body)
            return

        # Check agent_id-based rate limit to prevent targeted attacks
        # Default allows for agent retries (agent default is 3 retries, allow ~5 auth attempts)
        agent_rate_limit = config.getint("verifier", "session_create_rate_limit_per_agent", fallback=15)
        agent_rate_window = config.getint("verifier", "session_create_rate_limit_window_agent", fallback=60)

        allowed, retry_after = RateLimiter.check_rate_limit(
            f"agent:{agent_id}", max_requests=agent_rate_limit, window_seconds=agent_rate_window
        )
        if not allowed:
            error_body = {
                "errors": [
                    {
                        "status": "429",
                        "title": "Too Many Requests",
                        "detail": "Rate limit exceeded for this agent. Please try again later.",
                    }
                ]
            }
            self.action_handler.set_header("Retry-After", str(retry_after))
            self.send_response(code=429, body=error_body)
            return

        # Create session in memory (don't persist to DB yet)
        auth_session = AuthSession.create_in_memory(agent_id, params)

        if auth_session.get("errors"):
            msgs = []
            for field, errors in auth_session["errors"].items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            error_body = {"errors": [{"status": "400", "title": "Bad Request", "detail": msg} for msg in msgs]}
            self.send_response(code=400, body=error_body)
            return

        # Store in shared memory for access by other worker processes
        # Uses dual-key cache: primary by session_id, index by token_hash
        AuthSession.cache_session(auth_session)

        # Clean up stale sessions from shared memory
        AuthSession.delete_stale_from_memory(agent_id)

        # Send raw JSON-API response (not wrapped in {code, status, results})
        self.send_response(code=200, body=auth_session["response"])

    # PATCH /v3[.:minor]/sessions/:session_id
    def update_session(self, session_id, **params):
        """Update session with proof of possession.

        Returns 404 if session doesn't exist in shared memory.
        Returns 401 if authentication fails (invalid PoP or agent not enrolled).
        Returns 200 with token on success, and persists to database.
        """
        # Extract agent_id from request body
        logger.debug("PATCH /sessions/%s - params: %s", session_id, params)
        data = params.get("data", {})
        attributes = data.get("attributes", {})
        agent_id = attributes.get("agent_id")

        if not agent_id:
            logger.warning(
                "PATCH /sessions/%s - missing agent_id. Data: %s, Attributes: %s", session_id, data, attributes
            )
            error_body = {"errors": [{"status": "400", "title": "Bad Request", "detail": "agent_id is required"}]}
            self.send_response(code=400, body=error_body)
            return

        # Retrieve session from shared memory cache
        sessions_cache = AuthSession._get_sessions_cache()  # pylint: disable=protected-access
        auth_session_data = sessions_cache.get(session_id)

        if not auth_session_data:
            logger.error(
                "Session %s not found in cache. Available sessions: %s", session_id, list(sessions_cache.keys())
            )
            error_body = {"errors": [{"status": "404", "title": "Not Found", "detail": "Session not found"}]}
            self.send_response(code=404, body=error_body)
            return

        # Verify agent_id matches
        if auth_session_data.get("agent_id") != agent_id:
            error_body = {"errors": [{"status": "400", "title": "Bad Request", "detail": "Agent ID mismatch"}]}
            self.send_response(code=400, body=error_body)
            return

        # Verify nonce hasn't expired (prevent replay attacks)
        nonce_expires_at = auth_session_data.get("nonce_expires_at")
        if nonce_expires_at and nonce_expires_at < Timestamp.now():
            logger.warning("Nonce expired for session %s (agent %s)", session_id, agent_id)
            # Per spec: return 200 with evaluation:fail, not 401
            AuthSession.uncache_session(session_id)

            # Extract proof data from the request if provided
            data = params.get("data", {})
            attributes = data.get("attributes", {})
            auth_provided = attributes.get("authentication_provided", [])

            message = ""
            signature = ""
            if auth_provided and len(auth_provided) > 0:
                proof_data = auth_provided[0].get("data", {})
                message = proof_data.get("message", "")
                signature = proof_data.get("signature", "")

            response_body = {
                "data": {
                    "type": "session",
                    "id": session_id,
                    "attributes": {
                        "agent_id": agent_id,
                        "evaluation": "fail",
                        "authentication": [
                            {
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": base64.b64encode(auth_session_data.get("nonce")).decode("utf-8")  # type: ignore[arg-type]
                                },
                                "data": {"message": message, "signature": signature},
                            }
                        ],
                        "created_at": auth_session_data.get("nonce_created_at").isoformat(),  # type: ignore[union-attr]
                        "challenges_expire_at": nonce_expires_at.isoformat(),
                        "response_received_at": Timestamp.now().isoformat(),
                        "token_expires_at": None,
                    },
                }
            }
            self.send_response(code=200, body=response_body)
            return

        # Check if agent exists - this is where we validate enrollment
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        if not agent:
            # Agent not enrolled - return 200 with evaluation:fail
            # Per spec: authentication failures return 200 with evaluation:fail, not 401
            # No specific reason is given for the failure.
            logger.info("Authentication failed for unenrolled agent '%s'", agent_id)

            # Record when the response was received
            response_received_at = Timestamp.now()

            # Extract proof data from the request (may not be present for unenrolled agents)
            data = params.get("data", {})
            attributes = data.get("attributes", {})
            auth_provided = attributes.get("authentication_provided", [])

            # Extract message and signature if provided
            message = ""
            signature = ""
            if auth_provided and len(auth_provided) > 0:
                proof_data = auth_provided[0].get("data", {})
                message = proof_data.get("message", "")
                signature = proof_data.get("signature", "")

            # Build spec-compliant failure response
            response_data = {
                "data": {
                    "type": "session",
                    "id": session_id,  # JSON:API requires IDs to be strings
                    "attributes": {
                        "agent_id": agent_id,
                        "evaluation": "fail",
                        "authentication": [
                            {
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": base64.b64encode(auth_session_data.get("nonce")).decode("utf-8")  # type: ignore[arg-type]
                                },
                                "data": {"message": message, "signature": signature},
                            }
                        ],
                        "created_at": auth_session_data.get("nonce_created_at").isoformat(),  # type: ignore[union-attr]
                        "challenges_expire_at": auth_session_data.get("nonce_expires_at").isoformat(),  # type: ignore[union-attr]
                        "response_received_at": response_received_at.isoformat(),
                    },
                }
            }

            # Delete from shared memory (cache + token index)
            AuthSession.uncache_session(session_id)
            self.send_response(code=200, body=response_data)
            return

        # Verify PoP first - do NOT delete existing sessions until PoP succeeds
        # This prevents an attacker with a stolen session_id from invalidating a legitimate agent's sessions
        auth_session = AuthSession.create_from_memory(auth_session_data, agent, params)

        # Check if there are any actual errors (non-empty error lists)
        has_errors = any(errors for errors in auth_session.errors.values())

        if has_errors:
            msgs = []
            logger.error("auth_session.errors structure: %s", auth_session.errors)
            for field, errors in auth_session.errors.items():
                if errors:  # Only log fields that have errors
                    logger.error("Field '%s' has errors: %s", field, errors)
                    for error in errors:
                        msgs.append(f"{field} {error}")
            # Log the auth errors for debugging
            logger.error("Authentication failed for session %s: %s", session_id, msgs)

            # Build spec-compliant failure response per authentication-protocol.md
            # The response should include the authentication data that was provided
            # to allow the client to understand what went wrong
            response_data = {
                "data": {
                    "type": "session",
                    "id": session_id,
                    "attributes": {
                        "agent_id": auth_session.agent_id,
                        "evaluation": "fail",
                        "authentication": [
                            {
                                "authentication_class": "pop",
                                "authentication_type": "tpm_pop",
                                "chosen_parameters": {
                                    "challenge": base64.b64encode(auth_session.nonce).decode("utf-8")
                                },
                                "data": {
                                    "message": (
                                        base64.b64encode(auth_session.ak_attest).decode("utf-8")
                                        if auth_session.ak_attest
                                        else ""
                                    ),
                                    "signature": (
                                        base64.b64encode(auth_session.ak_sign).decode("utf-8")
                                        if auth_session.ak_sign
                                        else ""
                                    ),
                                },
                            }
                        ],
                        "created_at": auth_session.nonce_created_at.isoformat(),
                        "challenges_expire_at": auth_session.nonce_expires_at.isoformat(),
                        "response_received_at": auth_session.pop_received_at.isoformat(),
                    },
                }
            }

            # Delete from shared memory on failure (cache + token index)
            AuthSession.uncache_session(session_id)
            self.send_response(code=401, body=response_data)
            return

        # PoP verification succeeded - now safe to delete existing active sessions
        # This prevents multiple concurrent active sessions per agent
        # SECURITY: Only delete AFTER successful PoP to prevent session invalidation attacks
        logger.debug("PoP succeeded - deleting any existing active sessions for agent '%s'", agent_id)
        AuthSession.delete_active_session_for_agent(agent_id)

        # Persist to database
        auth_session.commit_changes()

        # Cache session for fast authentication lookups (avoids PBKDF2 on every request)
        # The plaintext token is stored in cache for fast comparison
        AuthSession.cache_session(
            {
                "session_id": session_id,
                "token": auth_session.token,  # Plaintext for fast cache comparison
                "token_salt": auth_session.token_salt,
                "token_hash": auth_session.token_hash,
                "agent_id": auth_session.agent_id,
                "active": True,
                "token_expires_at": auth_session.token_expires_at,
            }
        )

        # Build proper JSON-API response with required fields
        response_data = {
            "data": {
                "type": "session",
                "id": session_id,
                "attributes": {
                    "agent_id": auth_session.agent_id,
                    "evaluation": "pass",
                    "token": auth_session.token,
                    "authentication": [
                        {
                            "authentication_class": "pop",
                            "authentication_type": "tpm_pop",
                            "chosen_parameters": {"challenge": base64.b64encode(auth_session.nonce).decode("utf-8")},
                            "data": {
                                "message": (
                                    base64.b64encode(auth_session.ak_attest).decode("utf-8")
                                    if auth_session.ak_attest
                                    else ""
                                ),
                                "signature": (
                                    base64.b64encode(auth_session.ak_sign).decode("utf-8")
                                    if auth_session.ak_sign
                                    else ""
                                ),
                            },
                        }
                    ],
                    "created_at": auth_session.nonce_created_at.isoformat(),
                    "challenges_expire_at": auth_session.nonce_expires_at.isoformat(),
                    "response_received_at": auth_session.pop_received_at.isoformat(),
                    "token_expires_at": auth_session.token_expires_at.isoformat(),
                },
            }
        }
        self.send_response(code=200, body=response_data)

    # GET /v3[.:minor]/agents/:agent_id/session/:token
    def show(self, agent_id, token, **_params):
        AuthSession.delete_stale(agent_id)

        # Look up session by token hash (tokens are never stored in plaintext)
        auth_session = AuthSession.get_by_token(token)

        if not auth_session or auth_session.agent_id != agent_id:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        if not auth_session.active:  # type: ignore[attr-defined]
            self.respond(404, f"Agent with ID '{agent_id}' has not been activated")
            return

        self.respond(200, "Success", auth_session.render())

    # POST /v3[.:minor]/agents/:agent_id/session
    def create(self, agent_id, **params):
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        if not agent:
            self.respond(404, "here")
            return

        auth_session = AuthSession.create(agent, params)

        if auth_session.errors:
            msgs = []
            for field, errors in auth_session.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            self.respond(400, "Bad Request", {"errors": msgs})
            return

        AuthSession.delete_stale(agent_id)

        auth_session.commit_changes()
        self.respond(200, "Success", auth_session.render())

    def update(self, agent_id, token, **params):
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        # Look up session by token hash (tokens are never stored in plaintext)
        auth_session = AuthSession.get_by_token(token)

        if not auth_session or auth_session.agent_id != agent_id:
            self.respond(404)
            return

        auth_session.receive_pop(agent, params)  # type: ignore[attr-defined, arg-type]

        if auth_session.errors:  # type: ignore[attr-defined]
            # Log errors internally for debugging
            msgs = []
            for field, errors in auth_session.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            logger.error("Authentication failed for agent %s: %s", agent_id, msgs)

            auth_session.delete()
            # Per spec: return 200 with no error details (not 401)
            self.respond(200, "Authentication failed")
            return

        # AuthSession.delete_stale(agent_id)

        auth_session.commit_changes()
        self.respond(200, "Succeses", auth_session.render())
