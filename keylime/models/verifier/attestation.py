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
        cls._belongs_to("agent", verifier_models.VerifierAgent)
        cls._field("agent_id", String(80), primary_key=True, refers_to="agent.agent_id")
        cls._field("index", Integer, primary_key=True)
        # Each attestation is uniquely identifiable by an (agent_id, index) tuple; each agent has zero or more
        # attestations numbered incrementally from 0

        # ATTESTATION AND VERIFICATION STATUS
        cls._field("stage", OneOf("awaiting_evidence", "evaluating_evidence", "verification_complete"))
        cls._field("evaluation", OneOf("pending", "pass", "fail"))
        cls._field("failure_reason", OneOf("broken_evidence_chain", "policy_violation"), nullable=True)

        cls._has_many("evidence", verifier_models.EvidenceItem)
        cls._embeds_inline("system_info", SystemInfo)

        # TIMESTAMPS
        cls._field("capabilities_received_at", Timestamp)
        cls._field("challenges_expire_at", Timestamp, nullable=True)
        cls._field("evidence_received_at", Timestamp, nullable=True)
        cls._field("verification_completed_at", Timestamp, nullable=True)

    @classmethod
    def get_latest(cls, agent_id):
        # Fetch the last attestation entry in the database for a particular agent
        return Attestation.get(agent_id=agent_id, sort_=desc("index"))

    @classmethod
    def create(cls, agent):
        attestation = Attestation.empty()
        attestation.initialise(agent)
        return attestation

    def __init__(self, data=None, process_associations=True, memo=None) -> None:
        super().__init__(data, process_associations, memo)
        self._previous_attestation = None
        self._previous_authenticated_attestation = None
        self._previous_passed_attestation = None
        # self._evidence_requested = []

    def _set_index(self):
        if self.committed.get("index"):
            return

        last_attestation = Attestation.get_latest(self.agent_id)
        self.index = Attestation.get_latest(self.agent_id).index + 1 if last_attestation else 0

    def _set_stage(self):
        if self.evaluation and self.evaluation != "pending":
            self.stage = "verification_complete"
            return

        # if len(self.evidence) > 0:
        #     self.stage = "evaluating_evidence"
        #     return

        if self.evidence and all(item.data for item in self.evidence):
            self.stage = "evaluating_evidence"
            return

        self.stage = "awaiting_evidence"

    def _set_timestamps(self):
        now = Timestamp.now()

        if not self.capabilities_received_at and any(item.capabilities for item in self.evidence):
            self.capabilities_received_at = now

        if any(item.chosen_parameters and item.chosen_parameters.changes.get("challenge") for item in self.evidence):
            challenge_lifetime = config.getint("verifier", "challenge_lifetime", fallback=1800)
            self.challenges_expire_at = self.capabilities_received_at + timedelta(seconds=challenge_lifetime)

        if any(item.data and item.data.changes for item in self.evidence):
            self.evidence_received_at = now

        # for evidence_item in self.evidence:
        #     if not self.capabilities_received_at and evidence_item.capabilities:
        #         self.capabilities_received_at = now

        #     if evidence_item.chosen_parameters and evidence_item.chosen_parameters.changes.get("challenge"):
        #         challenge_lifetime = config.getint("verifier", "challenge_lifetime", fallback=1800)
        #         self.challenges_expire_at = self.capabilities_received_at + timedelta(seconds=challenge_lifetime)

        #     if evidence_item.data and evidence_item.data.changes:
        #         self.evidence_received_at = now

        # TODO: Set verification_completed_at

    def refresh_metadata(self):
        self._set_stage()
        self._set_timestamps()

    def initialise(self, agent):
        if self.committed:
            raise ValueError("Attestation object cannot be initialised once committed")

        # Set primary key using the agent_id and next available index
        self.agent = agent
        self._set_index()

        self.evaluation = "pending"
        self.refresh_metadata()

        # TODO: move to verification engine
        # last_attestation = Attestation.get_latest(agent.agent_id)
        # if not last_attestation and agent.next_ima_ml_entry:
        #     attestation.starting_ima_offset = agent.next_ima_ml_entry

    def receive_capabilities(self, data):
        evidence_data = data.get("evidence_supported", [])
        system_info_data = data.get("system_info", {})

        if not evidence_data:
            self._add_error("evidence", "is required")
            return

        if not isinstance(evidence_data, list):
            self._add_error("evidence", "must be an array")
            return

        for item_data in evidence_data:
            try:
                item = verifier_models.EvidenceItem.create(item_data)
                self.evidence.add(item)
            except TypeError:
                self._add_error("evidence", "may only contain objects with key-value pairs")

        self.system_info = SystemInfo.empty()
        self.system_info.update(system_info_data)

        self.refresh_metadata()

    def initialise_parameters(self):
        for item in self.evidence:
            item.initialise_parameters()

    def validate_parameters(self):
        for item in self.evidence:
            item.validate_parameters()

    def receive_evidence(self, data):
        evidence_data = data.get("evidence_collected", [])

        if not evidence_data:
            self._add_error("evidence", "is required")
            return

        if not isinstance(evidence_data, list):
            self._add_error("evidence", "must be an array")
            return

        if len(evidence_data) != len(self.evidence):
            self._add_error("evidence", "must contain a number of elements equal to that which were requested")
            return

        for i, item_data in enumerate(evidence_data):
            class_ = item_data.get("evidence_class")
            type_ = item_data.get("evidence_type")
            
            if not class_ == self.evidence[i].evidence_class or not type_ == self.evidence[i].evidence_type:
                self._add_error("evidence", "must appear in the same order as the evidence requested")
                return

            self.evidence[i].receive_evidence(item_data)

        self.refresh_metadata()

    def _render_timestamps(self):
        output = self.render(["capabilities_received_at"])

        if self.challenges_expire_at:
            output |= self.render(["challenges_expire_at"])

        if self.evidence_received_at:
            output |= self.render(["evidence_received_at"])

        if self.verification_completed_at:
            output |= self.render(["verification_completed_at"])

        return output

    def render_evidence_requested(self):
        output = self.render(["stage"])
        output["evidence_requested"] = [item.render_evidence_requested() for item in self.evidence]
        output["system_info"] = self.system_info.render()
        output |= self._render_timestamps()
        return output

    def render_evidence_acknowledged(self):
        output = self.render(["stage"])
        output["evidence"] = [item.render_evidence_acknowledged() for item in self.evidence]
        output["system_info"] = self.system_info.render()
        output |= self._render_timestamps()
        return output

    def render_state(self):
        output = self.render(["stage", "evaluation"])
        output["evidence"] = [item.render_state() for item in self.evidence]
        output["system_info"] = self.system_info.render()
        output |= self._render_timestamps()
        return output

    def commit_changes(self, session=None, persist=True):
        # Catch situation where multiple requests to create an attestation are received simultaneously
        if persist and self.stage == "awaiting_evidence":
            last_attestation = Attestation.get_latest(self.agent_id)

            if last_attestation and last_attestation.index >= self.index:
                raise ValueError(
                    f"An attestation for agent '{self.agent_id}' was created while another was mid-creation"
                )

        if persist and not session:
            # Accept changes and write them to the database (unless fields have errors)
            with db_manager.session_context_for(self, self.evidence) as session:
                super().commit_changes(session)

                for item in self.evidence:
                    item.commit_changes(session)
        else:
            super().commit_changes(session, persist)

            for item in self.evidence:
                item.commit_changes(session, persist)

        # TODO: Re-enable:
        #
        # # Write updated record to a durable attestation (DA) backend if configured
        # if da_manager.backend:
        #     attestation_data = {}

        #     # Prepare all record data to be sent to a DA backend according to each field's data type
        #     for name, field in self.__class__.fields.items():
        #         attestation_data[name] = field.data_type.da_dump(self.committed.get(name))

        #     # Write dumped data to DA backend as an "agent data" record
        #     da_manager.backend.record_create(None, attestation_data, None, None)

        # Note: Ideally one would want the DA code in keylime.da to be data agnostic (in the same way as a database
        # engine), so that writing to the DA backend could be handled transparently by PersistableModel. As this isn't
        # the case, it is necessary to override commit_changes and make the record_create call on a case-by-case basis.

    def get_errors(self, associations=None, pointer_prefix=None, memo=None):
        self.refresh_metadata()

        errors = super().get_errors(associations, pointer_prefix, memo)
        output = {}

        evidence_field = "evidence_supported" if self.stage == "awaiting_evidence" else "evidence_collected"

        for pointer, msgs in errors.items():
            if pointer.startswith("/evidence"):
                pointer = pointer.replace("/evidence", f"/{evidence_field}", 1)

            output[pointer] = msgs

        return output

    @property
    def previous_attestation(self):
        if not self._previous_attestation:
            if not self.agent_id:
                return None

            attestation = Attestation.get(
                Attestation.agent_id == self.agent_id,
                Attestation.index < self.index,
                sort_=desc("index")
            )

            if attestation:
                self._previous_attestation = attestation

        return self._previous_attestation

    @property
    def previous_authenticated_attestation(self):
        if not self._previous_authenticated_attestation:
            if not self.agent_id:
                return None

            attestation = Attestation.get(
                Attestation.agent_id == self.agent_id,
                Attestation.stage == "verification_complete",
                Attestation.failure_reason != "broken_evidence_chain",
                Attestation.index < self.index,
                sort_=desc("index")
            )

            if attestation:
                self._previous_authenticated_attestation = attestation

        return self._previous_authenticated_attestation

    @property
    def previous_passed_attestation(self):
        if not self._previous_passed_attestation:
            if not self.agent_id:
                return None

            attestation = Attestation.get(
                Attestation.agent_id == self.agent_id,
                Attestation.evaluation == "pass",
                Attestation.index < self.index,
                sort_=desc("index")
            )

            if attestation:
                self._previous_passed_attestation = attestation

        return self._previous_passed_attestation

    @property
    def decision_expected_by(self):
        if self.evidence_received_at:
            basis = self.evidence_received_at
        else:
            basis = self.challenges_expire_at

        return basis + timedelta(seconds=config.getint("verifier", "verification_timeout"))

    @property
    def seconds_to_decision(self):
        time_to_decision = self.decision_expected_by - Timestamp.now()
        seconds_to_decision = round(time_to_decision.total_seconds())

        if seconds_to_decision <= 0:
            return 0

        return seconds_to_decision

    @property
    def next_attestation_expected_after(self):
        if self.evidence_received_at:
            return self.evidence_received_at + timedelta(seconds=config.getint("verifier", "quote_interval"))
        else:
            return self.capabilities_received_at

    @property
    def seconds_to_next_attestation(self):
        time_to_next_attestation = self.next_attestation_expected_after - Timestamp.now()
        seconds_to_next_attestation = round(time_to_next_attestation.total_seconds())

        if seconds_to_next_attestation <= 0:
            return 0

        return seconds_to_next_attestation

    @property
    def challenges_valid(self):
        return bool(self.challenges_expire_at and Timestamp.now() < self.challenges_expire_at)

    @property
    def verification_in_progress(self):
        return bool(self.stage == "evaluating_evidence" and self.seconds_to_decision > 0)

    @property
    def ready_for_next_attestation(self):
        return bool(not self.verification_in_progress and self.seconds_to_next_attestation <= 0)


class SystemInfo(PersistableModel):
    @classmethod
    def _schema(cls):
        cls._field("boot_time", Timestamp, nullable=True)

    def update(self, data):
        self.cast_changes(data, ["boot_time"])

    def render(self, only=None):
        if only is None:
            only = []

            if self.boot_time:
                only.append("boot_time")

        return super().render(only)
