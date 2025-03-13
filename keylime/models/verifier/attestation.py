from datetime import timedelta

from keylime import config, keylime_logging
from keylime.models.base import *
import keylime.models.verifier as verifier_models

logger = keylime_logging.init_logging("verifier")


class Attestation(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._persist_as("attestations")

        # IDENTIFIERS
        cls._belongs_to("agent", verifier_models.VerifierAgent, primary_key=True)
        cls._field("index", Integer, primary_key=True)
        # Each attestation is uniquely identifiable by an (agent_id, index) tuple; each agent has zero or more
        # attestations numbered incrementally from 0

        # ATTESTATION AND VERIFICATION STATUS
        # Indicates the state of the attestation
        cls._field("status", OneOf("waiting", "received", "verified", "failed"))
        # Indicates the type of failure in case of failed verification
        cls._field("failure_type", OneOf("quote_authentication", "policy_violation"), nullable=True)

        cls._has_many("evidence", verifier_models.EvidenceItem)
        cls._embeds_one("system_info", SystemInfo)

        # TIMESTAMPS
        cls._field("capabilities_received_at", Timestamp)
        cls._field("challenges_expire_at", Timestamp)
        cls._field("evidence_received_at", Timestamp, nullable=True)
        cls._field("verification_completed_at", Timestamp, nullable=True)

    def _prepare_timestamps(self):
        now = Timestamp.now()

        # TODO: Change below if statement to check for changes to capabilities directly
        if not self.capabilities_received_at:
            self.capabilities_received_at = now

        for evidence_item in self.evidence:
            new_challenge = evidence_item.chosen_parameters.changes.get("challenge")

            if self.capabilities_received_at and new_challenge:
                challenge_lifetime = config.getint("verifier", "challenge_lifetime")
                self.challenges_expire_at = self.capabilities_received_at + timedelta(challenge_lifetime)
                break

            if evidence_item.data.changes:
                self.evidence_received_at = now
                break

            # TODO: Set verification_completed_at

    def initialise(self, agent):
        if self.committed:
            raise ValueError("Attestation object cannot be initialised once committed")

        self.agent = agent

        # Set attestation index to the next available integer as determined from the agent's last attestation
        # self._set_index()

        # Set required metadata
        self._prepare_timestamps()
        # self._set_status()

    def receive_capabilities(self, data):
        # if data.get("evidence_requested") or data.get("evidence_collected") or data.get("evidence"):
        pass

    def receive_evidence(self, data):
        pass


class SystemInfo(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._field("boot_time", Timestamp, nullable=True)

    def update(self, data):
        self.cast_changes(data, ["boot_time"])
