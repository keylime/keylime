from functools import cache

from keylime.models.base import *
import keylime.models.verifier as verifier_models

from keylime.mba import mba
from keylime import config
from keylime.common import algorithms

from keylime.db.verifier_db import JSONPickleType
from keylime.json import JSONPickler

class VerifierAgent(PersistableModel):

    @classmethod
    def _schema(cls):
        cls._persist_as("verifiermain")
        cls._id("agent_id", String(80))

        # Associations
        cls._belongs_to("ima_policy", verifier_models.IMAPolicy)
        cls._field("ima_policy_id", Integer, refers_to="ima_policy.id")
        cls._belongs_to("mb_policy", verifier_models.MBPolicy)
        cls._field("mb_policy_id", Integer, refers_to="mb_policy.id")
        cls._has_many("attestations", verifier_models.Attestation, preload=False)

        # The attestation key (AK) used by the TPM to sign attestations
        cls._field("ak_tpm", Binary(persist_as=String(500)))
        # Arbitrary metadata about the agent which includes info about the agent's cert if configured to use mTLS
        cls._field("meta_data", String(200))

        # Describes the expected values for the TPM's platform configuration registers (PCRs)
        cls._field("tpm_policy", Dictionary)

        # Fields for runtime integrity monitoring (Linux IMA)
        cls._field("learned_ima_keyrings", Dictionary)

        # Allowable cryptographic algorithms to accept from the TPM
        cls._field("accept_tpm_hash_algs", List)
        cls._field("accept_tpm_encryption_algs", List)
        cls._field("accept_tpm_signing_algs", List)

        # Metrics and timestamps
        cls._field("attestation_count", Integer)

        # ------------------------------------------------------------------ #
        # PUSH-MODE ONLY FIELDS:

        # Indicates whether attestations will be accepted for this agent
        cls._field("accept_attestations", Boolean)

        # ------------------------------------------------------------------ #
        # PULL-MODE ONLY FIELDS:

        # TODO: replace with SQLAlchemy Enum datatype
        cls._field("operational_state", Integer, nullable=True)
        cls._field("severity_level", Integer, nullable=True)

        cls._field("v", String(45), nullable=True)
        cls._field("public_key", String(500), nullable=True)
        # cls._field("mtls_cert", Certificate, nullable=True)
        cls._field("ip", String(15), nullable=True)
        cls._field("port", Integer, nullable=True)
        cls._field("verifier_id", String(80), nullable=True)
        cls._field("verifier_ip", String(15), nullable=True)
        cls._field("verifier_port", Integer, nullable=True)

        # The API version which should be used when contacting the agent
        cls._field("supported_version", String(20), nullable=True)

        # Cryptographic algorithms used to produce quotes
        cls._field("hash_alg", String(10), nullable=True)
        cls._field("enc_alg", String(10), nullable=True)
        cls._field("sign_alg", String(10), nullable=True)

        # Fields for runtime integrity monitoring (Linux IMA)
        cls._field("ima_sign_verification_keys", Text, nullable=True)
        cls._field("ima_pcrs", List, nullable=True)
        cls._field("pcr10", Binary, nullable=True)
        cls._field("next_ima_ml_entry", Integer, nullable=True)

        # Other miscellaneous measures of system state
        cls._field("boottime", Integer, nullable=True)
        cls._field("tpm_clockinfo", Dictionary, nullable=True)

        # Metrics and timestamps
        cls._field("last_received_quote", Integer, nullable=True)
        cls._field("last_successful_attestation", Integer, nullable=True)

        # ------------------------------------------------------------------ #
        # QUESTION FOR REVIEWERS:
        # Are these fields for revocation still needed or can we remove them?
        cls._field("tpm_version", Integer, nullable=True) # VERDICT: DROP
        cls._field("revocation_key", String(2800)) # Revocation still supported; keep pull-only, output warning
        cls._field("last_event_id", String(200), nullable=True) # Pull only possibly. Anderson will investigate further
        # ------------------------------------------------------------------ #
        # TODO: remove above, based on feedback

    @property
    @cache
    def latest_attestation(self):
        return verifier_models.Attestation.get_latest(self.agent_id)
