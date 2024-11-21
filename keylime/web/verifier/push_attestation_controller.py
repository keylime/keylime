import sys
import time

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from keylime import keylime_logging
from keylime.db.keylime_db import DBEngineManager, SessionManager
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist, VerifierAttestations, VerifierMbpolicy
from keylime.models.base import Timestamp
from keylime.models.verifier import PushAttestation
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")

# GLOBAL_POLICY_CACHE: Dict[str, Dict[str, str]] = {}

try:
    engine = DBEngineManager().make_engine("cloud_verifier")
except SQLAlchemyError as err:
    logger.error("Error creating SQL engine or session: %s", err)
    sys.exit(1)


def get_session() -> Session:
    return SessionManager().make_session(engine)


class PushAttestationController(Controller):
    """
    The Push Attestation Controller services requests for the management of attestation resources. Such attestation
    resources are represented by instances of the ``Attestation`` model.

    Attestation evidence is prepared and sent according the push attestation protocol::

                          Agent                                       Verifier
                          -----                                       --------
                            │                                             │
                            │               1. Capabilities               █
                            │ <-----------------------------------------> █
                            │        i.e. supported TPM algorithms        █
                            │                                             █
                            │                                             █   Create
                            │          2. Attestation Parameters          █
                            │ <-----------------------------------------> █
                            │   i.e. ima offset, chosen algorithms, etc   █
                            │                                             │
                            │                                             │
                            │                 3. Evidence                 █
                            │ <-----------------------------------------> █
                            │      i.e. quote, UEFI log, IMA log, etc     █
                            │                                             █
                            │                                             █   Update
                            │                 4. Response                 █
                            │ <-----------------------------------------> █
                            │   i.e. whether the request appread well-    █
                            │                    formed                   │
                            │                                             │


    Attestation Lifecycle
    -----------------------

    The lifecycle of an ``Attestation`` object is managed by the Push Attestation Controller according to various
    values, chief among them that of the ``status`` field. This field may be set to any of the following values:

        * "waiting": Indicates the attestation has been created and initialized with values such as the nonce
        * "received": Indicates the expected evidence has been received
        * "verified": Indicates the evidence has verified against policy successfully
        * "failed": Indicates verification of the evidence has completed but the evidence did not comply with policy

    The status of an attestation is not reported to the agent as the verification outcome is not known until after
    requests have completed.

    Previous attestations are retained according to the following rules:

        * The last attestation is retained if its status is verified or failed.
        * The first attestation received after a reboot is always retained.
        * Once an attestation is verified, the previous attestation is deleted if its status is also verified unless the
          preceeding rule applies.
        * Failed attestations are always retained.
        * If an attestation is created while the previous attesation has a status of waiting, that previous attestation
          is replace by the new attestation.
        * If an attesation is created while the previous attestation has a status of received and the verification
          timeout has been exceeded, the previous attestaion is replaced by the new attestation.

    A request to create a new attestation is rejected under the following circumstances:

        * If the attestation creation request is for an agent which has its ``accept_attestations`` flag set to false
        * If the attestation creation request is received before the quote interval has elasped.
        * If the attestation creation request is received before verification of the last attestation has completed
          assuming the verification timeout has not been exceeded
    """

    # GET /v2[.:minor]/agents/:agent_id/attestations
    def index(self, agent_id, **_params):
        results = PushAttestation.all(agent_id=agent_id)

        self.respond(200, "Sucess", [attestation.render() for attestation in results])

    # GET /v2[.:minor]/agents/:agent_id/attestations/:index
    def show(self, agent_id, index, **_params):
        attestation = PushAttestation.get(agent_id=agent_id, index=index)

        if not attestation:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        self.respond(200, "Success", attestation.render())

    # GET /v2[.:minor]/agents/:agent_id/attestations/latest
    def show_latest(self, agent_id, **_params):
        last_attestation = PushAttestation.get_last(agent_id=agent_id)

        if not last_attestation:
            self.respond(404, f"Agent with ID '{agent_id}' not found")
            return

        self.respond(200, "Success", last_attestation.render())

    # POST /v2[.:minor]/agents/:agent_id/attestations
    def create(self, agent_id, **params):
        # TODO: Replace with calls to VerifierAgent.get(...)
        # get agent from verifiermain
        session = get_session()
        # agent = session.query(VerfierMain).filter(VerifierAttestations.agent_id == agent_id).one_or_none()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()

        if not agent:
            self.respond(404)
            return

        if agent.accept_attestations is False:
            self.respond(503)
            return """

        """  # Reject request if a previous attestation is still being processed
        retry_seconds = PushAttestation.accept_new_attestations_in(agent_id)

        if retry_seconds:
            self.action_handler.set_header("Retry-After", retry_seconds)
            self.respond(429)
            return

        new_attestation = PushAttestation.create(agent_id, agent, params)

        if new_attestation.errors:
            msgs = []
            for field, errors in new_attestation.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            self.respond(400, "Bad Request", {"errors": msgs})
            return

        try:
            new_attestation.commit_changes()
        except ValueError:
            # Another attestation for this agent was created while this request is being processed. Reject the request
            # as otherwise the new attestation may be created prior to or shortly after evidence is received and
            # processed for the other attestation, meaning that the configured quote interval would not be respected
            self.respond(429)
            return
        
        # The attestation was created successfully, so delete any previous attestation for which evidence was never
        # received or for which verification never completed
        new_attestation.cleanup_stale_priors()

        response = new_attestation.render(
            [
                "agent_id",
                "nonce",
                "nonce_created_at",
                "nonce_expires_at",
                "status",
                "hash_alg",
                "enc_alg",
                "sign_alg",
                "starting_ima_offset",
            ]
        )
        response = {**response, "pcr_mask": agent.tpm_policy}
        self.respond(200, "Success", response)

    def update(self, agent_id, **params):
        # TODO: Replace with calls to VerifierAgent.get(...) and IMAPolicy.get(...)
        session = get_session()
        agent = session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).one_or_none()
        allowlist = session.query(VerifierAllowlist).filter(VerifierAllowlist.id == agent.ima_policy_id).one_or_none()
        mbpolicies = session.query(VerifierMbpolicy).filter(VerifierMbpolicy.id == agent.mb_policy_id).one_or_none()

        # get last attestation entry for the agent
        attestation = PushAttestation.get_last(agent_id=agent_id)

        if not attestation:
            self.respond(404)
            return

        if attestation.status != "waiting":
            self.respond(403)
            return

        if attestation.nonce_expires_at < Timestamp.now():
            self.respond(400, "too many request")
            return

        attestation.receive_evidence(params, allowlist.ima_policy)

        # last_attestation will contain errors if the JSON request is malformed/invalid (e.g., if an unrecognised hash
        # algorithm is provided) but not if the quote verification fails (including if the quote cannot be verified as
        # authentic, if the IMA/MB logs cannot be verified as authentic, or if the logs do not meet policy)
        if not attestation.changes_valid:
            msgs = []
            for field, errors in attestation.errors.items():
                for error in errors:
                    msgs.append(f"{field} {error}")
            self.respond(400, "Bad Request", {"errors": msgs})
            return

        session.add(agent)

        attestation.commit_changes()
        time_to_next_attestation = attestation.next_attestation_expected_after - Timestamp.now()
        response = {"time_to_next_attestation": int(time_to_next_attestation.total_seconds())}
        self.respond(200, "Success", response)

        # Verify attestation after response is sent, so that the agent does not need to wait for the verification to
        # complete. Ideally, in the future, we would want to create a pool of verification worker processes
        # (separate from the web server workers) which will call this method whenever a new verification task is added
        # to a queue
        attestation.verify_evidence(allowlist.ima_policy, mbpolicies.mb_policy, agent, session)

        session.commit()
