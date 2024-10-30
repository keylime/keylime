import json
import time
from typing import Optional

from keylime import config, keylime_logging
from keylime.agentstates import AgentAttestStates
from keylime.common import algorithms
from keylime.failure import Component, Failure
from keylime.ima import file_signatures
from keylime.models.base import *
from keylime.tpm.tpm_main import Tpm

logger = keylime_logging.init_logging("verifier")

GLOBAL_TPM_INSTANCE: Optional[Tpm] = None


def get_tpm_instance() -> Tpm:
    global GLOBAL_TPM_INSTANCE
    if GLOBAL_TPM_INSTANCE is None:
        GLOBAL_TPM_INSTANCE = Tpm()
    return GLOBAL_TPM_INSTANCE


def get_AgentAttestStates() -> AgentAttestStates:
    return AgentAttestStates.get_instance()


class PushAttestation(PersistableModel):
    """An instance of the PushAttestation class is used to manage state over the lifetime of an attestation received
    from an agent as a single push attestation is performed over multiple HTTP requests. When the push attestation
    protocol starts, the verifier receives a list of capabilities of the agent system and generates a nonce in response.
    The agent prepares evidence based on the nonce and the attestation method chosen by the verifier. This is sent in a
    second HTTP request as shown in the below diagram::

                      Agent                                       Verifier
                      -----                                       --------    PushAttestation
                        │                                             │            object
                        │    1. Attestation parameter negotiation     │      ┌────────────────┐
                        │ <-----------------------------------------> │ <--> │ ** Created **  │
                        │                                             │      │       │        │
                        │         2. Submission of evidence           │      │       ↓        │
                        │ <-----------------------------------------> │ <--> │ ** Updated **  │
                        │                                             │      │       │        │
                                                                             │       ↓        │
                                                                             │ ** Verified ** │
                                                                             └────────────────┘

    PushAttestation records are persisted to the database to ensure continuity across worker processes and across
    restarts of the verifier. These are cleaned up automatically to prevent exponential expansion of the stored data but
    a minimal history of the last few attestations are kept for audit and reporting purposes.

    Class Usage
    -----------

    When it is time to report the next scheduled attestation, the agent makes a POST request over HTTPS to the verifier.
    The request body consists of a list of TPM algorithms supported by the agent and these are used to create a new
    PushAttestation object by invoking the ``PushAttestation.create(agent_id, data)`` class method.

    The PushAttestation class determines the following values which are returned to the agent in the HTTP response:

        * A new randomly-generated nonce for the TPM to include in the quote
        * A mask indicating which PCRs should be included in the quote
        * An offset value indicating which IMA log entries should be sent by the agent
        * TPM algorithms to be used for the quote
        * The timestamp at which the nonce was generated
        * The time at which the nonce will expire calculated from the period configured by the user

    These values are persisted to the database by calling ``attestation.commit_changes()``.

    The agent gathers the evidence (UEFI log, IMA entries and quote) required for the verification using the values
    received from the verifier (such as the chosen TPM algorithms) and reports the prepared evidence by submitting a
    PUT request to the verifier. The verifier retrieves the attestation record from the database by calling
    ``PushAttestation.get_last(agent_id)`` and updates it with the received evidence by calling
    ``attestation.update(data)``.

    The verifier will reply with the number of seconds the agent should wait before performing the next attestation
    (obtained from ``attestation.next_attestation_expected_after``) and an indication of whether the request from
    the agent appeared well formed.

    Actual processing and verification of the measurements against policy is performed after the response is returned by
    calling ``attestation.verify_evidence()``.


    PushAttestation Lifecycle
    ---------------------

    For details on the lifecycle of an PushAttestation object, refer to the documentation for
    ``keylime.web.verifier.push_attestation_controller``.


    Management of IMA Logs
    ----------------------

    The agent reports a list of IMA measurements as part of the evidence for an attestation. The number of IMA
    measurement entries received are retained as `ima_count`. The list of IMA measurements to be reported for the
    verification is determined by the verifier as follows:

        * When an attestation request is initialised, the verfier checks if there was a previous successful attestation.
        * If there is no such attestation, the `starting_ima_offset` value for the newly created attestation is set to
          0  and the agent to expected to send the IMA measurements starting from the first entry.
        * If there was a previous successful attestation, the `starting_ima offset` value for the new attestation is
          calculated based on the `starting_ima_offset` value of the last successful attestation plus its `ima_count` .
          The verifier replies to the attestation initiation request with `starting_ima_offset` value calculated for the
          new attesation and the is agent to expected to send the IMA measurements starting from this value.

    The IMA entries received for the attestation are retained and undergoes under verfication. It is not expected to
    store all attestations in the database therefore only the subset of IMA measurements are persited.


    Management of Measured Boot (UEFI) Logs
    ---------------------------------------

    The agent reports the measured boot log if measured boot attestation if implemented. The measured boot log received
    for each attestation is retained.
    """

    def __init__(self, data: dict | object | None = None, process_associations: bool = True) -> None:
        super().__init__(data, process_associations)
        self._previous_successful_attestation = None
        self._previous_attestation = None

    @classmethod
    def _schema(cls):
        cls._persist_as("attestations")
        # TODO: Uncomment
        # cls._belongs_to("agent", VerifierAgent, inverse_of="attestations", preload = False)
        cls._field("agent_id", String(80), primary_key=True)  # pylint: disable=unexpected-keyword-arg
        # The nonce to be used by the agent for an Attestation
        cls._field("nonce", Nonce)
        # The timestamp of when the nonce was created
        cls._field("nonce_created_at", Integer, primary_key=True)  # pylint: disable=unexpected-keyword-arg
        # The timestamp of when the nonce is expired
        cls._field("nonce_expires_at", Integer)
        # Indicates the state of the attestation
        cls._field("status", OneOf("waiting", "received", "verified", "failed"), nullable=False)
        # The tpm quote from the agent
        cls._field("tpm_quote", Text)  # JEAN: Change to Binary type?
        # The timestamp of when the quote was received
        cls._field("evidence_received_at", Integer)
        # The PCRs and hash of the PCRs in the tpm quote
        cls._field("tpm_pcrs", Text)  # TODO: Change to type Dictionary
        # The starting ima offset for an Attestation
        cls._field("starting_ima_offset", Integer)
        # The tpm hashing algorithm to be used by agent
        cls._field("hash_alg", String(10))
        ## The tpm encryption algorithm to be used by agent
        cls._field("enc_alg", String(10))
        # The tpm signing algorithm to be used by agent
        cls._field("sign_alg", String(10))
        # The ima entries count of an Attestation
        cls._field("ima_count", Integer)
        # The ima entries from the agent
        cls._field("ima_entries", Text)
        # The measured boot entries from the agent
        cls._field("mb_entries", Text)

    @classmethod
    def create(cls, agent_id, agent, data):
        """Create an empty Attestation and prepare the attestation details(nonce, timestamps of nonce, algorithms)

        :param data: list of TPM algorithms supported by the agent

        :returns: Attestation object

        """

        attestation = PushAttestation.empty()
        attestation.agent_id = agent_id
        # Generate and set the nonce for the attestation entry
        attestation._set_nonce()
        # Set the timestamp related to nonce (created at, expires at)
        attestation._set_timestamps()
        # Set the status of the attesation ('waiting' when a new attestation is created)
        attestation._set_status()
        # Set the ima offset value for the attestation entry
        attestation.starting_ima_offset = attestation._set_ima_offset()
        # Set the TPM algorithms to be used for the attestation from the list of supported algorithms provided by the
        # agent
        attestation._set_algs(
            data.get("supported_hash_algs"), data.get("supported_enc_algs"), data.get("supported_sign_algs"), agent
        )
        return attestation

    @classmethod
    def get_last(cls, agent_id):
        # Fetch the last attestation entry in the database for a particular agent
        all_attestations = PushAttestation.all(agent_id=agent_id)
        all_attestations = sorted(all_attestations, key=lambda attestation: attestation.nonce_created_at)
        return all_attestations[-1]

    @classmethod
    def load_from_agent(cls, agent, session):
        # Migrating from verifiermain table for pull mode compatibility
        attestation = PushAttestation.empty()
        attestation.agent_id = agent.agent_id
        attestation.hash_alg = agent.hash_alg
        attestation.enc_alg = agent.enc_alg
        attestation.sign_alg = agent.sign_alg
        attestation.starting_ima_offset = agent.next_ima_ml_entry
        attestation.evidence_received_at = agent.last_received_tpm_quote
        # attestation.tpm_pcrs = { 10: agent.pcr10 }
        attestation.commit_changes()

        agent.hash_alg = None
        agent.enc_alg = None
        agent.sign_alg = None
        agent.next_ima_ml_entry = None
        agent.last_received_tpm_quote = None
        # agent.pcr10 = None

        session.add(agent)
        session.commit()

        return attestation

        # TODO: Implement inverse of this function for when mode is changed from push to pull

    @classmethod
    def get_last_successful(cls, agent_id):
        # Fetch the last successful attestation entry from the attestation table for a particular agent
        return PushAttestation.get(agent_id=agent_id, status="verified")

    def _set_nonce(self):
        if "nonce" not in self.values:
            self.nonce = Nonce.generate(128)

    def _set_timestamps(self):
        current_timestamp = int(time.time())
        nonce_lifetime = config.getint("verifier", "nonce_lifetime")

        if self.changes.get("nonce"):
            self.nonce_created_at = current_timestamp
            self.nonce_expires_at = self.nonce_created_at + nonce_lifetime

        if self.changes.get("tpm_quote"):
            self.evidence_received_at = current_timestamp

    def _set_status(self):
        if not self.status:
            self.status = "waiting"

        if self.changes.get("tpm_quote"):
            self.status = "received"

        # status will be set to either "verified" or "failed" after tpm_quote verification is performed by
        # _verify_evidence()

    def _set_ima_offset(self):
        if self.previous_successful_attestation:
            self.starting_ima_offset = self.previous_successful_attestation.next_ima_offset
        else:
            self.starting_ima_offset = 0
        return self.starting_ima_offset

    def _set_algs(self, supported_hash_algs, supported_enc_algs, supported_sign_algs, agent):
        # Resolving the below pylint warning would negatively impact the readability of this method definition
        # pylint: disable=no-else-break

        # Set hashing algorithm that is first match from the list of hashing supported by the agent tpm
        # and the list of accpeted hashing algorithm
        for hash_alg in agent.accept_tpm_hash_algs:
            if hash_alg in supported_hash_algs:
                self.hash_alg = hash_alg
                break
            else:
                self._add_error(
                    "hash_alg", f"does not contain any accepted hashing algorithm for agent '{agent.agent_id}'"
                )

        # Set encryption algorithm that is first match from the list of encryption supported by the agent tpm
        # and the list of accpeted encryption algorithm
        for enc_alg in agent.accept_tpm_encryption_algs:
            if enc_alg in supported_enc_algs:
                self.enc_alg = enc_alg
                break
            else:
                self._add_error(
                    "enc_alg", f"supported_enc_alg not in list of accpeted_tpm_enc_algs for agent '{agent.agent_id}'"
                )

        # Set signing algorithm that is first match from the list of signing supported by the agent tpm
        # and the list of accpeted signing algorithm
        for sign_alg in agent.accept_tpm_signing_algs:
            if sign_alg in supported_sign_algs:
                self.sign_alg = sign_alg
                break
            else:
                self._add_error(
                    "sign_alg", f"supported_sign_alg not in list of accpeted_tpm_sign_algs for agent '{agent.agent_id}'"
                )

    def _validate_ima_offset(self, starting_ima_offset):
        if starting_ima_offset != self.starting_ima_offset:
            self._add_error("starting_ima_offset", "is not the expected starting ima offset for this attestation")

    def _parse_evidence(self, ima_entries, mb_entries, agent):
        # TODO: Rename "_extract_fields_from_tpm_quote"
        tpm_pcrs_dict = Tpm.get_pcrs_from_quote(self.tpm_quote, (agent.supported_version == "1.0"))
        tpm_pcrs_dict = {int(num): val for num, val in tpm_pcrs_dict.items()}
        self.tpm_pcrs = json.dumps(tpm_pcrs_dict)
        self.mb_entries = mb_entries  # TODO revisit data type for mb and ima entries

        if ima_entries:
            self.ima_count = ima_entries.count("\n")
            self.ima_entries = ima_entries

    def update(self, data, agent):
        """Updates the attestation entry with evidence recieved from the agent"""
        # Bind key-value pairs ('data') to those fields which are meant to be externally changeable
        self.cast_changes(data, ["tpm_quote", "ima_entries", "mb_entries"])

        # Basic validation of values
        self.validate_required(["tpm_quote", "hash_alg", "enc_alg", "sign_alg"])
        self._validate_ima_offset(data.get("starting_ima_offset"))

        # Parse the evidence recieved from the agent
        self._parse_evidence(self.ima_entries, self.mb_entries, agent)
        # Set the attestation status ('received' when the TPM quote is received from the agent)
        self._set_status()
        # Set the timepstamp of when the quote was received
        self._set_timestamps()

    def verify_evidence(self, runtime_policy, mb_policy: Optional[str], agent, session):
        """Verifies the evidence recieved from the agent and set the attestation status. ('verified' or 'failed' based
        on verification)
        If the verification of the measurements fails against the policy, ``accept_attestation`` flag is set to False.
        This stops verifier from accepting new attestation until the ``accept_attestation`` flag is set to True by the
        user.

        """
        # TODO: Replace session
        failure = Failure(Component.QUOTE_VALIDATION)
        pub_key = None
        ima_entries = self.ima_entries or None
        mb_entries = self.mb_entries or None
        # TODO add support for receiving ak_tpm from agent for an attestation
        ak_tpm = agent.ak_tpm
        tpm_policy = agent.tpm_policy

        if not self.changes_valid:
            raise ValueError("Attestation object cannot be verified as it has pending changes with errors")

        if not self.tpm_quote:
            raise ValueError("Attestation object has no tpm_quote")

        if self.status in ("verified", "failed"):
            raise ValueError("Attestation object has already undergone verification")

        # TODO: Get IMA PCR (usually PCR 10) from self.previous_successful_attestation.tpm_pcrs
        ima_pcr_dict = {pcr_num: getattr(agent, f"pcr{pcr_num}") for pcr_num in agent.ima_pcrs}

        if not get_AgentAttestStates().map.get(self.agent_id):
            get_AgentAttestStates().add(
                self.agent_id, agent.boottime, ima_pcr_dict, self.starting_ima_offset, agent.learned_ima_keyrings
            )

        agentAttestState = get_AgentAttestStates().get_by_agent_id(self.agent_id)

        if self.starting_ima_offset == 0:
            agentAttestState.reset_ima_attestation()
        elif self.starting_ima_offset != agentAttestState.get_next_ima_ml_entry():
            # If we requested a particular entry number then the agent must return either
            # starting at 0 (handled above) or with the requested number.
            self._add_error(
                "starting_ima_offset",
                "agent did not respond with a list of IMA events starting from the expected entry",
            )
            # TODO (for Jean): Add virtual fields to PersistableModel so that we can add an error to an "ima_entries" field
            # TODO (for Jean): Move this check into "receive_tpm_quote/extract_fields_from_tpm_quote"
            return

        if isinstance(runtime_policy, str):
            runtime_policy = json.loads(runtime_policy)

        ima_keyrings = agentAttestState.get_ima_keyrings()
        verification_key_string = runtime_policy["verification-keys"]
        tenant_keyring = file_signatures.ImaKeyring.from_string(verification_key_string)
        ima_keyrings.set_tenant_keyring(tenant_keyring)

        quote_validation_failure = get_tpm_instance().check_quote(
            agentAttestState,
            self.nonce,
            pub_key,
            self.tpm_quote,
            ak_tpm,
            tpm_policy,
            ima_entries,
            runtime_policy,
            algorithms.Hash(self.hash_alg),
            ima_keyrings,
            mb_entries,
            mb_policy,
            compressed=(agent.supported_version == "1.0"),
            count=agent.attestation_count,
        )
        failure.merge(quote_validation_failure)

        if failure:
            self.status = "failed"
            agent.accept_attestations = False
            logger.warning(
                "tpm_Quote for agent '%s' failed verification because of the following reasons:", self.agent_id
            )

            for event in failure.events:
                logger.warning("  - %s", event.context)
        else:
            if self.previous_attestation and self.previous_attestation.status == "verified":
                self.previous_attestation.delete()

            self.status = "verified"
            agent.attestation_count += 1
            agent.tpm_clockinfo = json.dumps(agentAttestState.get_tpm_clockinfo().to_dict())
            agent.last_successful_attestation = int(time.time())
            logger.info("tpm_Quote for agent '%s':", self.agent_id)
        session.add(agent)
        self.commit_changes()

    def render(self, only=None):
        if not only:
            only = ["agent_id", "status", "tpm_quote", "evidence_received_at", "tpm_pcrs", "starting_ima_offset"]

        return super().render(only)

    @property
    def previous_successful_attestation(self):
        if not self._previous_successful_attestation:
            if not self.agent_id:
                return None

            all_attestations = PushAttestation.all(agent_id=self.agent_id, status="verified")
            all_attestations = sorted(
                all_attestations, key=lambda attestation: attestation.nonce_created_at, reverse=True
            )

            previous_successful_attestation = None
            for attestation in all_attestations:
                if attestation.nonce_created_at < self.nonce_created_at:
                    previous_successful_attestation = attestation

            if not previous_successful_attestation:
                return None

            self._previous_successful_attestation = previous_successful_attestation

        return self._previous_successful_attestation

    @property
    def previous_attestation(self):
        if not self._previous_attestation:
            if not self.agent_id:
                return None

            all_attestations = PushAttestation.all(agent_id=self.agent_id)
            all_attestations = sorted(
                all_attestations, key=lambda attestation: attestation.nonce_created_at, reverse=True
            )

            previous_attestation = None
            for attestation in all_attestations:
                if attestation.nonce_created_at < self.nonce_created_at:
                    previous_attestation = attestation

            if not previous_attestation:
                return None

            self._previous_attestation = previous_attestation

        return self._previous_attestation

    @property
    def next_ima_offset(self):
        return self.starting_ima_offset + self.ima_count

    @property
    def next_attestation_expected_after(self):
        return self.evidence_received_at + config.getint("verifier", "quote_interval")

    @property
    def decision_expected_by(self):
        return self.evidence_received_at + config.getint("verifier", "verification_timeout")
