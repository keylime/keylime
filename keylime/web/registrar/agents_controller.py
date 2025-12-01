from keylime import keylime_logging
from keylime.models import RegistrarAgent
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
        """
        # Attempt to load existing agent, or create new empty agent
        agent = RegistrarAgent.get(agent_id) or RegistrarAgent.empty()  # type: ignore[no-untyped-call]

        # Update agent with new data (this includes TPM identity validation)
        agent.update({"agent_id": agent_id, **params})  # type: ignore[union-attr]

        # Check specifically for TPM identity change security violation
        # The update() method will have added an error to "agent_id" field if identity changed
        if not agent.changes_valid and "agent_id" in agent.errors:  # type: ignore[union-attr]
            # Check if this is a TPM identity security violation (vs other validation error)
            agent_id_errors = agent.errors.get("agent_id", [])  # type: ignore[union-attr]
            is_tpm_identity_violation = any("different TPM identity" in str(err) for err in agent_id_errors)

            if is_tpm_identity_violation:
                # Log the validation errors (includes security warning)
                self.log_model_errors(agent, logger)

                # Return 403 Forbidden (not 400 Bad Request)
                # 403 indicates a policy violation, not a malformed request
                self.respond(403, "Agent re-registration with different TPM identity is forbidden for security reasons")
                return

        # Generate AK challenge (encrypts nonce with EK)
        # This will return None if EK/AIK are invalid
        challenge = agent.produce_ak_challenge()  # type: ignore[union-attr]

        # Check for any validation errors or challenge generation failure
        if not challenge or not agent.changes_valid:
            self.log_model_errors(agent, logger)
            self.respond(400, "Could not register agent with invalid data")
            return

        # Save agent to database (still in inactive state until challenge response verified)
        agent.commit_changes()

        # Return challenge blob for agent to decrypt
        self.respond(200, "Success", {"blob": challenge})

    # DELETE /v2[.:minor]/agents/:agent_id/
    def delete(self, agent_id, **_params):
        agent = RegistrarAgent.get(agent_id)

        if not agent:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        agent.delete()
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

            self.respond(
                400,
                f"Auth tag '{auth_tag}' for agent '{agent_id}' does not match expected value. The agent has been "
                f"deleted from the database and will need to be restarted to reattempt registration",
            )
