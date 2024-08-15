import time
import json
from typing import Optional

from keylime.models.base import *
from keylime.tpm import tpm_util
from keylime.tpm.tpm_main import Tpm
from keylime import config, keylime_logging
from keylime.attestationstatus import AttestationStatusEnum
from keylime.common import algorithms
from keylime.agentstates import  AgentAttestStates
from keylime.failure import Component, Failure
from keylime.ima import file_signatures


logger = keylime_logging.init_logging("verifier")

GLOBAL_TPM_INSTANCE: Optional[Tpm] = None

def get_tpm_instance() -> Tpm:
    global GLOBAL_TPM_INSTANCE
    if GLOBAL_TPM_INSTANCE is None:
        GLOBAL_TPM_INSTANCE = Tpm()
    return GLOBAL_TPM_INSTANCE

def get_AgentAttestStates() -> AgentAttestStates:
        return AgentAttestStates.get_instance()

class Attestation(PersistableModel):

    _previous_successful_attestation = None
    
    @classmethod
    def _schema(cls):
        cls._persist_as("attestations")
        #cls._belongs_to("agent", VerifierAgent, inverse_of="attestations", preload = False)
        cls._field("agent_id", String(80), primary_key = True)
        cls._field("nonce", String(20))
        cls._field("nonce_created", Integer, primary_key = True)
        cls._field("nonce_expires", Integer)
        cls._field("status", Enum(AttestationStatusEnum))
        cls._field("quote", Text)
        cls._field("quote_received", Integer)
        cls._field("pcrs", Text)
        cls._field("next_ima_offset",Integer)
        cls._field("hash_alg",String(10))
        cls._field("enc_alg", String(10))
        cls._field("sign_alg", String(10))

    @classmethod
    def create(cls, agent_id):
        attestation = Attestation.empty()
        attestation.agent_id = agent_id
        attestation._set_nonce()
        attestation._set_status()
        attestation._set_timestamps()
        return attestation
    
    @classmethod
    def get_last(cls, agent_id):
        all_attestations = Attestation.all(agent_id = agent_id)
        all_attestations = sorted(all_attestations, key=lambda attestation: attestation.nonce_created)
        return all_attestations[-1]

    @classmethod
    def get_last_successful(cls, agent_id):
        return Attestation.get_one(agent_id = agent_id, status = "VERIFIED")

    def _set_status(self):
        
        if not self.status:
            self.status = AttestationStatusEnum.WAITING

        if self.changes.get("quote"):
            self.status = AttestationStatusEnum.RECEIVED
        
        # status will be set to either VERIFIED or FAILED after quote verification is performed by _verify_quote()
    
    def _set_timestamps(self):

        current_timestamp = int(time.time())
        nonce_lifetime = config.getint("verifier","nonce_lifetime")

        if self.changes.get("nonce"):
            self.nonce_created = current_timestamp
            self.nonce_expires = self.nonce_created + nonce_lifetime
 
        if self.changes.get("quote"):
            self.quote_received = current_timestamp

    def _validate_algs(self, agent):

        # Ensure tpm hash algorithm in accepted algorithm list
        if self.hash_alg not in agent.accept_tpm_hash_algs:
            self._add_error("hash_alg", f"is not an acceptable hash algorithm for agent '{agent.agent_id}'" )
        
        # Ensure encryption algorithm in accepted algorithm list
        if self.enc_alg not in agent.accept_tpm_encryption_algs:
            self._add_error("enc_alg", "is unaccepted hash algorithm")
        
        # Ensure signing algorithm in accepted algorithm list
        if self.sign_alg not in agent.accept_tpm_signing_algs:
            self._add_error("enc_alg", "is unaccepted hash algorithm")
    
    def _set_nonce(self):
        if "nonce" not in self.values:
            self.nonce = tpm_util.random_password(20)
    
    def _receive_quote(self, ima_events, agent):

        # TODO: Rename "_extract_fields_from_quote"
        
        pcrs_dict = Tpm.get_pcrs_from_quote(self.quote, (agent.supported_version == "1.0"))
        self.pcrs = json.dumps(pcrs_dict)
        
        if ima_events:
            self.next_ima_offset = self.starting_ima_offset + ima_events.count('\n')

    def update(self, data, agent):
        self.cast_changes(data, ["quote", "hash_alg", "enc_alg", "sign_alg"])
        ima_events = data.get("ima_events")
        self.validate_required(["quote", "hash_alg", "enc_alg", "sign_alg"])
        self._validate_algs(agent)
        self._receive_quote(ima_events, agent)
        self._set_status()
        self._set_timestamps()

    def verify_quote(self, data, runtime_policy, mb_policy: Optional[str], agent):

        failure = Failure(Component.QUOTE_VALIDATION)
        
        pub_key = None
        ima_events = data.get("ima_events") or None
        mb_events = data.get("mb_events") or None
        ak_tpm = data.get("ak_tpm") or agent.ak_tpm

        if not self.changes_valid:
            raise ValueError("Attestation object cannot be verified as it has pending changes with errors")

        if not self.quote:
            raise ValueError("Attestation object has no quote")

        if self.status == AttestationStatusEnum.VERIFIED or self.status == AttestationStatusEnum.FAILED:
            raise ValueError("Attestation object has already undergone verification")
        
        ima_pcr_dict = { pcr_num: getattr(agent, f"pcr{pcr_num}") for pcr_num in agent.ima_pcrs }
        
        if not get_AgentAttestStates().map.get(self.agent_id):
            get_AgentAttestStates().add(self.agent_id, agent.boottime, ima_pcr_dict, self.starting_ima_offset, agent.learned_ima_keyrings)

        agentAttestState = get_AgentAttestStates().get_by_agent_id(self.agent_id)
        
        if self.starting_ima_offset == 0:
            agentAttestState.reset_ima_attestation()
        elif self.starting_ima_offset != agentAttestState.get_next_ima_ml_entry():
            # If we requested a particular entry number then the agent must return either
            # starting at 0 (handled above) or with the requested number.
            self._add_error("next_ima_offset", "agent did not respond with a list of IMA events starting from the expected entry")
            # TODO (for Jean): Add virtual fields to PersistableModel so that we can add an error to an "ima_events" field
            # TODO (for Jean): Move this check into "receive_quote/extract_fields_from_quote"
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
            self.quote,
            ak_tpm,
            '{"mask":"0xfffe"}',
            ima_events,
            runtime_policy,
            algorithms.Hash(self.hash_alg),
            ima_keyrings,
            mb_events,
            mb_policy,
            compressed=(agent.supported_version == "1.0"),
            count=agent.attestation_count,)
        
        failure.merge(quote_validation_failure)

        if failure: 
            self.status = AttestationStatusEnum.FAILED
            logger.warning("Quote for agent '%s' failed verification because of the following reasons:", self.agent_id)

            for event in failure.events:
                logger.warning("  - %s", event.context)
        else:
            self.status = AttestationStatusEnum.VERIFIED
            agent.attestation_count += 1
            agent.tpm_clockinfo = json.dumps(agentAttestState.get_tpm_clockinfo().to_dict())
            agent.last_successful_attestation = int(time.time())
            logger.info("Quote for agent '%s':", self.agent_id)

        self.commit_changes()

    def render(self, only=None):
        if not only:
            only = ["agent_id", "status", "quote", "quote_received", "pcrs","next_ima_offset"]

        return super().render(only)
    
    @property
    def previous_successful_attestation(self):
        if not self._previous_successful_attestation:
            if not self.agent_id:
                return None
            
            attestation = Attestation.get_one(agent_id = self.agent_id, status = "VERIFIED")

            if not attestation:
                return None
            
            if attestation.nonce_created >= self.nonce_created:
                return None
            
            self._previous_successful_attestation = attestation
        
        return self._previous_successful_attestation
    
    @property
    def starting_ima_offset(self):
        if self.previous_successful_attestation:
            starting_ima_offset = self.previous_successful_attestation.next_ima_offset or 0
        else:
            starting_ima_offset = 0

        return starting_ima_offset