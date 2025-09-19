from keylime import keylime_logging
from keylime.models.base import Timestamp
from keylime.models.verifier import VerifierAgent, Attestation
from keylime.verification import EngineDriver
from keylime.web.base import Controller, APIMessageBody, APIResource, APIError, APILink, APIMeta

logger = keylime_logging.init_logging("web")


class AttestationController(Controller):
    """The AttestationController services requests for the management of attestation resources when the verifier is
    operating in push mode. Such attestation resources are represented by instances of the ``Attestation`` model.

    Attestation evidence is prepared and sent according the push attestation protocol which operates in two phases::

                          Agent                                           Verifier
                          -----                                           --------
                            │                                                 │
                        ┬   │                 1. Capabilities                 █─────────────────┐
                        │   │ ----------------------------------------------> █                 │
             1st Phase: │   │         i.e., supported TPM algorithms          █   Attestation   │
           ------------ │   │                                                 █    resource     │
           CAPABILITIES │   │                                                 █     created     │
            NEGOTIATION │   │            2. Attestation Parameters            █                 │
                        │   │ <---------------------------------------------- █        │        │
                        ┴   │    i.e., ima offset, chosen algorithms, etc.    █────────│────────┘
                            │                                                 │        │
                            │                                                 │        │
                        ┬   │                   3. Evidence                   █────────│────────┐
                        │   │ ----------------------------------------------> █        🡓        │
             2nd Phase: │   │       i.e., quote, UEFI log, IMA log, etc.      █   Attestation   │
             ---------- │   │                                                 █    resource     │
               EVIDENCE │   │                                                 █     updated     │
               HANDLING │   │                   4. Response                   █                 │
                        │   │ <---------------------------------------------- █                 │
                        ┴   │  i.e., whether the request appears well-formed  █─────────────────┘
                            │                                                 │


    Identifying Attestation Resources
    ---------------------------------

    Each attestation resource is scoped to an agent and is identified by an auto-incrementing index (starting from 0).
    While this index may be used to reference a particular attestation, most often it is the latest attestation which is
    relevant. Routes are therefore provided (in ``keylime.web.verifier_server``) to GET and PATCH the latest attestation
    resource. Requests which match these routes are handled by the ``show_latest`` and ``update_latest`` actions
    respectively.

    The following paths may therefore refer to the same attestation resource if a total of five (5) attestations exist
    for agent 1:
    
        * /v3/agents/1/attestations/4
        * /v3/agents/1/attestations/latest

    Lifetime of an Attestation Resource
    -----------------------------------

    Even though every attestation resource is uniquely identifiable by an ``(agent_id, index)`` tuple, attestation
    resources are not accessible indefinitely forever. This is because old attestations records are automatically
    cleared to limit the storage requirements of the database.

    Generally, the latest attestation and any attestations which fail verification are always retained. The specifics
    are documented in `keylime.models.verifier.push_attestation`.

    Creating Attestation Resources
    ------------------------------
    
    An attestation resource is only creatable under certain conditions to enforce correct behaviour of untrusted agents
    which may make requests to the verifier at will.

    A request to create a new attestation resource may fail for any of the following reasons:

        * the agent does not exist (404 "Not Found");
        * attestations are disabled for the agent, e.g., if a previous verification failed (403 "Forbidden");
        * the request has been received too soon after evidence was received for the previous attestation (429 "Too Many
          Requests");
        * verification of a previous attestation is still in progress (503 "Service Unavailable");
        * the request data is not valid despite having the right syntax (422 "Unprocessable Content");
        * the request data cannot be accepted for some other reason, such as having an incorrect Content-Type (200 "Bad 
          Request"); or
        * the request was received while another request to create an attestation resource was still being processed
          (409 "Conflict").

    In all cases other than the first two, the request may be re-attempted. When a 429 or 503 status is returned, the
    ``Retry-After`` HTTP header indicates the number of seconds after which the request will be accepted.

    Details about each error condition can be found by inspecting the ``errors`` structure in the JSON response.
    
    Mutating Attestation Resources
    ------------------------------
    
    Any given attestation resource may only be updated once after creation to supply the evidence for the attestation.
    At this point, assuming the received evidence is in the expected format, the resource becomes immutable for the
    remainder of its lifetime.

    A request to update an attestation resource may fail for any of the following reasons:

        * the attestation resource never existed (404 "Not Found");
        * the attestation resource no longer exists (410 "Gone");
        * the attestation resource has already been updated with the expected evidence (403 "Forbidden");
        * the nonce for the attestation resource has expired (403 "Forbidden");
        * the evidence provided was not as expected (400 "Bad Request"); or
        * too many worker processes are currently occupied by a verification task (503 "Service Unavailable").

    In the final two cases, the request may be re-attempted. When a 503 status is returned, the ``Retry-After`` HTTP
    header indicates the estimated number of seconds after which the verifier will accept the evidence.
    
    In all other cases, a new attestation resource must first be created before the verifier will accept evidence from
    that specific agent.

    Details about each error condition can be found by inspecting the ``errors`` structure in the JSON response.

    Performance Considerations
    --------------------------

    In general, the cooperative multitasking of the underlying web framework ensures that long-running I/O tasks do
    not block a worker process from handling other requests in the interim. However, because verification is largely a
    CPU-bound task, when a worker is busy processing a verification, that process is blocked until the task is complete.
    A number of mechanisms have been implemented to limit this impact, some of which are user-configurable:

        * To prevent the verifier from being overloaded with constant attestations from an individual agent, creation of
          a new attestation is not allowed until a certain amount of time has passed since evidence was received for the
          agent's previous attestation. This is determined by the ``quote_interval`` config option which is also used to
          determine the ``next_attestation_expected_after`` ISO datetime returned to the agent when valid evidence is
          received. The user should set ``quote_interval`` based on their desired attestation frequency.

        * To prevent attestations from taking so long as to exhaust the verifier's resources, e.g., if an agent, perhaps
          maliciously, sends an excessive amount of data as evidence, the verifier will give up trying to verify an 
          attestation after a certain cut off is reached. This is determined by the ``verification_timeout`` config
          option. When set to 0 (the default), verifications will time out after m*3 seconds where m is the average time
          taken to process attestations since the verifier was started. When a value > 0 is given, this is interpreted
          as a fixed timeout in seconds.

        * To allow the verifier to respond to requests even when many attestations are received all at once, a number of
          worker processes are kept free for request handling and will not perform verification tasks. This number is
          usually determined by the formula floor(n*r) where n is the total number of workers and r is the percentage
          which will dedicated to servicing incoming requests. When the formula returns <1, a single dedicated worker is
          used. But when n equals one, a warning is produced as no process can be dedicated. The value of r is 25% by
          default but may be overriden by setting the ``dedicated_web_workers`` config value to a different percentage.
          Alternatively, a fixed number may be provided instead.

    Additionally:

        * Regardless of how long a verification task takes, it will not block the verifier from issuing its response to
          the agent which submitted the evidence.

        * When an agent submits evidence but all the worker processes which are not dedicated to request handling are
          occupied by a verification task, the verifier will instruct the agent to wait a certain amount of time before
          retrying. This value is determined by the formula n*m where n is a count of the requests which the verifier 
          has had to reject for this reason (including the current request) and m is the average number of seconds the
          verifier has taken to complete each verification task since starting. The value n is reset to 0 when enough
          workers become available to service more verification tasks.
    """

    # GET /v3[.:minor]/agents/:agent_id/attestations
    @Controller.require_json_api
    def index(self, agent_id, **_params):
        agent = VerifierAgent.get(agent_id)

        if not agent:
            APIError("not_found", f"No enrolled agent with ID '{agent_id}'.").send_via(self)
        
        results = Attestation.all(agent_id=agent_id)

        resources = [
            APIResource("attestation", attestation.render_state()).include(
                APILink("self", f"{self.path}/{attestation.index}")
            )
            for attestation in results
        ]

        APIMessageBody(*resources).send_via(self)

    # GET /v3[.:minor]/agents/:agent_id/attestations/:index
    @Controller.require_json_api
    def show(self, agent_id, index, **_params):
        agent = VerifierAgent.get(agent_id)
        attestation = Attestation.get(agent_id=agent_id, index=index)

        if not agent:
            APIError("not_found", f"No enrolled agent with ID '{agent_id}'.").send_via(self)

        if not attestation:
            APIError("not_found", f"No attestation {index} exists for agent '{agent_id}'.").send_via(self)

        APIResource("attestation", attestation.render_state()).include(
            APILink("self", f"/{self.version}/agents/{agent_id}/attestations/{index}")
        ).send_via(self)

    # GET /v3[.:minor]/agents/:agent_id/attestations/latest
    @Controller.require_json_api
    def show_latest(self, agent_id, **_params):
        agent = VerifierAgent.get(agent_id)

        if not agent:
            APIError("not_found", f"No enrolled agent with ID '{agent_id}'.").send_via(self)

        if not agent.latest_attestation:
            APIError("not_found", f"No attestation exists for agent '{agent_id}'.").send_via(self)

        self.show(agent_id, agent.latest_attestation.index, **_params)

    # POST /v3[.:minor]/agents/:agent_id/attestations
    @Controller.require_json_api
    def create(self, agent_id, attestation, **params):
        agent = VerifierAgent.get(agent_id)

        if not agent:
            APIError("not_found", f"No enrolled agent with ID '{agent_id}'.").send_via(self)

        if not agent.accept_attestations:
            APIError("agent_attestations_disabled", 403).set_detail(
                f"Attestations for agent '{agent_id}' are currently disabled. This may be due to a previous "
                f"attestation not passing verification."
            ).send_via(self)

        if agent.latest_attestation and agent.latest_attestation.verification_in_progress:
            self.set_header("Retry-After", agent.latest_attestation.seconds_to_decision)
            APIError("verification_in_progress", 503).set_detail(
                f"Cannot create attestation for agent '{agent_id}' while the last attestation is still being "
                f"verified. The active verification task is expected to complete or time out within "
                f"{agent.latest_attestation.seconds_to_decision} seconds."
            ).send_via(self)

        if agent.latest_attestation and not agent.latest_attestation.ready_for_next_attestation:
            self.set_header("Retry-After", agent.latest_attestation.seconds_to_next_attestation)
            APIError("premature_attestation", 429).set_detail(
                f"Cannot create attestation for agent '{agent_id}' before the configured interval has elapsed. "
                f"Wait {agent.latest_attestation.seconds_to_next_attestation} seconds before trying again."
            ).send_via(self)

        attestation_record = Attestation.create(agent)
        attestation_record.receive_capabilities(attestation)
        EngineDriver(attestation_record).process_capabilities()

        if not attestation_record.changes_valid:
            APIMessageBody.from_record_errors(attestation_record).send_via(self)

        try:
            attestation_record.commit_changes()
        except ValueError:
            # Another attestation for this agent was created while this request is being processed. Reject the request
            # as otherwise the new attestation may be created prior to or shortly after evidence is received and
            # processed for the other attestation, meaning that the configured quote interval would not be respected
            APIError("conflict").set_detail(
                f"Cannot create attestation for agent '{agent_id}' while another creation attempt is in progress."
            ).send_via(self)

        # TODO: Re-enable:
        # # The attestation was created successfully, so delete any previous attestation for which evidence was never
        # # received or for which verification never completed
        # attestation_record.cleanup_stale_priors()

        log_data = (attestation_record.index, agent_id)
        logger.info("Created attestation %s for agent '%s', sending chosen parameters", *log_data)

        APIResource("attestation", attestation_record.render_evidence_requested()).include(
            APILink("self", f"{self.path}/{attestation_record.index}")
        ).send_via(self)

    # PATCH /v3[.:minor]/agents/:agent_id/attestations/:index
    @Controller.require_json_api
    def update(self, agent_id, index, attestation, **params):
        agent = VerifierAgent.get(agent_id)

        if not agent:
            APIError("not_found", f"No enrolled agent with ID '{agent_id}'.").send_via(self)

        # If there are no attestations for the agent, the attestation at 'index' does not exist
        if not agent.latest_attestation:
            APIError("not_found", f"No attestation {index} exists for agent '{agent_id}'.").send_via(self)

        # Only allow the attestation at 'index' to be updated if it is the latest attestation
        if str(agent.latest_attestation.index) != index:
            APIError("old_attestation", 403).set_detail(
                f"Attestation {index} is not the latest for agent '{agent_id}'. Only evidence for the most recent "
                f"attestation may be updated."
            ).send_via(self)

        if agent.latest_attestation.stage != "awaiting_evidence":
            APIError("evidence_immutable", 403).set_detail(
                f"Cannot alter evidence for attestation {index} which has already been received and accepted."
            ).send_via(self)

        if not agent.latest_attestation.challenges_valid:
            APIError("challenges_expired", 403).set_detail(
                f"Challenges for attestation {index} expired at {agent.latest_attestation.challenges_expire_at}. "
                f"Create a new attestation and try again."
            ).send_via(self)

        agent.latest_attestation.receive_evidence(attestation)
        driver = EngineDriver(agent.latest_attestation).process_evidence()

        # Send error if the received evidence appears invalid
        if not agent.latest_attestation.changes_valid:
            APIMessageBody.from_record_errors(agent.latest_attestation).send_via(self)

        agent.latest_attestation.commit_changes()

        # Send acknowledgement of received evidence, but continue executing
        APIMessageBody(
            APIResource("attestation", agent.latest_attestation.render_evidence_acknowledged()).include(
                APILink("self", f"/{self.version}/agents/{agent_id}/attestations/{index}")
            ),
            APIMeta("seconds_to_next_attestation", agent.latest_attestation.seconds_to_next_attestation)
        ).send_via(self, code=202, stop_action=False)

        # Verify attestation after response is sent, so the agent does not need to wait for verification to complete
        driver.verify_evidence()

    # PATCH /v3[.:minor]/agents/:agent_id/attestations/latest
    @Controller.require_json_api
    def update_latest(self, agent_id, attestation, **params):
        agent = VerifierAgent.get(agent_id)

        if not agent:
            APIError("not_found", f"No enrolled agent with ID '{agent_id}'.").send_via(self)

        if not agent.latest_attestation:
            APIError("not_found", f"No attestation exists for agent '{agent_id}'.").send_via(self)

        self.update(agent_id, agent.latest_attestation.index, attestation, **params)
