from sqlalchemy.exc import IntegrityError

from keylime import keylime_logging
from keylime.models import RegistrarAgent
from keylime.shared_data import get_shared_memory
from keylime.web.base import Controller

logger = keylime_logging.init_logging("registrar")


class AgentsController(Controller):
    # GET /v2[.:minor]/agents/
    def index(self, **_params):
        results = RegistrarAgent.all_ids()

        self.respond(200, "Success", {"uuids": results})

    # GET /v2[.:minor]/agents/:agent_id/
    def show(self, agent_id, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        if not agent.active:  # type: ignore[attr-defined]
            self.respond(404, f"Agent with ID '{agent_id}' has not been activated")
            return

        self.respond(200, "Success", agent.render())

    # POST /v2[.:minor]/agents/[:agent_id]
    def create(self, agent_id, **params):
        """Register a new agent or re-register an existing agent.

        For new agents, this:
        1. Validates TPM identity (EK/AIK or IAK/IDevID)
        2. Generates an AK challenge encrypted with the EK
        3. Stores agent record in pending state
        4. Returns challenge blob to agent

        For existing agents (re-registration with same UUID):
        1. Verifies TPM identity has not changed (security check)
        2. If identity changed: rejects with 403 Forbidden
        3. If identity same: allows re-registration (e.g., after agent restart)

        Security: Re-registration with a different TPM is forbidden to prevent
        UUID spoofing attacks where an attacker could impersonate a legitimate
        agent by reusing its UUID.

        Race condition protection: Uses per-agent locks from SharedDataManager to prevent
        race conditions between concurrent registration requests for the same agent_id.
        This ensures the check-validate-commit sequence is atomic. Additionally, database
        constraint violations (e.g., duplicate UUIDs from concurrent requests) are caught
        and returned as 403 Forbidden.
        """
        # Get shared memory manager and per-agent lock storage
        shared_mem = get_shared_memory()
        agent_locks = shared_mem.get_or_create_dict("agent_registration_locks")

        # Get or create a lock specific to this agent_id
        if agent_id not in agent_locks:
            agent_locks[agent_id] = shared_mem.manager.Lock()

        agent_lock = agent_locks[agent_id]

        # CRITICAL SECTION: Acquire lock to make check-validate-commit atomic
        with agent_lock:
            # Step 1: Load existing agent or create new one (inside lock)
            agent = RegistrarAgent.get(agent_id) or RegistrarAgent.empty()  # type: ignore[no-untyped-call]

            # Step 2: Update agent with new data and validate (inside lock)
            agent.update({"agent_id": agent_id, **params})  # type: ignore[union-attr]

            # Step 3: Check for TPM identity change security violation
            if not agent.changes_valid and "agent_id" in agent.errors:  # type: ignore[union-attr]
                # Check if this is a TPM identity security violation (vs other validation error)
                agent_id_errors = agent.errors.get("agent_id", [])  # type: ignore[union-attr]
                is_tpm_identity_violation = any("different TPM identity" in str(err) for err in agent_id_errors)

                if is_tpm_identity_violation:
                    # Log the validation errors (includes security warning)
                    self.log_model_errors(agent, logger)

                    # Return 403 Forbidden
                    # 403 indicates a policy violation, not a malformed request
                    self.respond(
                        403, "Agent re-registration with different TPM identity is forbidden for security reasons"
                    )
                    return

            # Step 4: Generate AK challenge (inside lock)
            challenge = agent.produce_ak_challenge()  # type: ignore[union-attr]

            # Step 5: Check for any validation errors or challenge generation failure
            if not challenge or not agent.changes_valid:
                self.log_model_errors(agent, logger)
                self.respond(400, "Could not register agent with invalid data")
                return

            # Step 6: Commit to database (inside lock)
            # This ensures no other request can modify the agent between validation and commit
            try:
                agent.commit_changes()
            except IntegrityError as e:
                # Database constraint violation - most likely duplicate agent_id
                # This can happen if two requests try to register the same new UUID simultaneously
                # and both pass validation before either commits (database race condition)
                logger.warning(
                    "SECURITY: Agent registration failed due to database constraint violation for agent_id '%s'. "
                    "This UUID may already be registered by a concurrent request or the agent already exists. "
                    "Database error: %s",
                    agent_id,
                    str(e),
                )
                self.respond(
                    403,
                    f"Agent with UUID '{agent_id}' cannot be registered. "
                    "This UUID is already in use or a concurrent registration is in progress.",
                )
                return

        # Lock released - safe to respond to client
        # Return challenge blob for agent to decrypt
        self.respond(200, "Success", {"blob": challenge})

    # DELETE /v2[.:minor]/agents/:agent_id/
    def delete(self, agent_id, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        agent.delete()

        # Clean up the registration lock from shared memory to prevent memory leak
        shared_mem = get_shared_memory()
        agent_locks = shared_mem.get_or_create_dict("agent_registration_locks")
        agent_locks.pop(agent_id, None)

        self.respond(200, "Success")

    # POST /v2[.:minor]/agents/:agent_id/[activate]
    def activate(self, agent_id, auth_tag, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        accepted = agent.verify_ak_response(auth_tag)  # type: ignore[attr-defined]

        if accepted:
            agent.commit_changes()
            self.respond(200, "Success")
        else:
            agent.delete()

            # Clean up the registration lock from shared memory to prevent memory leak
            shared_mem = get_shared_memory()
            agent_locks = shared_mem.get_or_create_dict("agent_registration_locks")
            agent_locks.pop(agent_id, None)

            self.respond(
                400,
                f"Auth tag '{auth_tag}' for agent '{agent_id}' does not match expected value. The agent has been "
                f"deleted from the database and will need to be restarted to reattempt registration",
            )
