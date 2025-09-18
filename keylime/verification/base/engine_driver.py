import copy
import re
from typing import overload

from keylime.verification.base.verification_engine import VerificationEngine
from keylime.verification.base.verification_engine_meta import VerificationEngineMeta
from keylime.models.base import db_manager

class EngineDriver:

    _parameter_mutators = {}
    _evidence_evaluators = {}

    @overload
    @classmethod
    def register_parameter_mutator(cls, engine: VerificationEngineMeta, evidence_type: str) -> None:
        ...

    @overload
    @classmethod
    def register_parameter_mutator(cls, engine: VerificationEngineMeta, evidence_types: tuple[str, ...]) -> None:
        ...

    @classmethod
    def register_parameter_mutator(cls, engine: VerificationEngineMeta, evidence_types: str | tuple[str, ...]) -> None:
        if not issubclass(engine, VerificationEngine):
            raise TypeError("only a subclass of VerificationEngine can be registered as a parameter mutator")

        if not isinstance(evidence_types, tuple):
            evidence_types = (evidence_types)

        for evidence_type in evidence_types:
            if not isinstance(evidence_type, str):
                raise TypeError("parameter mutator can only be registered for evidence types given as strings")

            if not re.fullmatch("[a-z0-9_]+", evidence_type):
                raise TypeError(f"evidence type '{evidence_type}' not given in snake case")

            if not cls._parameter_mutators.get(evidence_type):
                cls._parameter_mutators[evidence_type] = []

            cls._parameter_mutators[evidence_type].append(engine)

    @overload
    @classmethod
    def register_evidence_evaluator(cls, engine: VerificationEngineMeta, evidence_type: str) -> None:
        ...

    @overload
    @classmethod
    def register_evidence_evaluator(cls, engine: VerificationEngineMeta, evidence_types: tuple[str, ...]) -> None:
        ...

    @classmethod
    def register_evidence_evaluator(cls, engine: VerificationEngineMeta, evidence_types: str | tuple[str, ...]) -> None:
        if not issubclass(engine, VerificationEngine):
            raise TypeError("only a subclass of VerificationEngine can be registered as a evidence evaluator")

        if not isinstance(evidence_types, tuple):
            evidence_types = (evidence_types)

        for evidence_type in evidence_types:
            if not isinstance(evidence_type, str):
                raise TypeError("evidence evaluator can only be registered for evidence types given as strings")

            if not re.fullmatch("[a-z0-9_]+", evidence_type):
                raise TypeError(f"evidence type '{evidence_type}' not given in snake case")

            if not cls._evidence_evaluators.get(evidence_type):
                cls._evidence_evaluators[evidence_type] = []

            cls._evidence_evaluators[evidence_type].append(engine)

    @classmethod
    def get_parameter_mutators(cls, evidence_type: str):
        if not isinstance(evidence_type, str):
            raise TypeError("evidence type must be given as a string")

        return cls._parameter_mutators.get(evidence_type)

    @classmethod
    def get_evidence_evaluators(cls, evidence_type: str):
        if not isinstance(evidence_type, str):
            raise TypeError("evidence type must be given as a string")

        return cls._evidence_evaluators.get(evidence_type)
    
    @classmethod
    def is_parameter_mutator(cls, engine, evidence_type):
        return engine in self.get_parameter_mutators(evidence_item.evidence_type)

    @classmethod
    def is_evidence_evaluator(cls, engine, evidence_type):
        return engine in self.get_evidence_evaluators(evidence_item.evidence_type)

    def __init__(self, attestation):
        self._attestation = attestation

    def process_capabilities(self):
        if not self.attestation.changes_valid:
            return self

        self.attestation.initialise_parameters()

        evidence_requested = []
        engines_to_activate = set()

        for item in self.attestation.evidence:
            engines_to_activate.update(self.get_parameter_mutators(item.evidence_type))

        for engine in engines_to_activate:
            evidence_snapshot = evidence_requested.copy()
            engine(self.attestation).process_capabilities(evidence_requested)

            if self.attestation.get_errors():
                return self
            
            if not set(evidence_snapshot).issubset(set(evidence_requested)):
                raise ValueError(
                    f"verification engine '{engine.__class__.__name__}' removed an item from the append-only "
                    f"'evidence_requested' list"
                )

        # TODO: finalise evidence requested
        self.attestation.evidence.clear()
        self.attestation.evidence.update(evidence_requested)
        self.attestation.validate_parameters()

        return self

    def process_evidence(self):
        if not self.attestation.changes_valid:
            return self

        engines_to_activate = set()

        for item in self.attestation.evidence:
            engines_to_activate.update(self.get_evidence_evaluators(item.evidence_type))

        for engine in engines_to_activate:
            engine(self.attestation).process_evidence()

            if self.attestation.get_errors():
                return self

        return self

    def _commit_verification_results(self):
        affected_records = [self.attestation, self.attestation.evidence, self.attestation.agent]

        with db_manager.session_context_for(*affected_records) as session:
            self.attestation.agent.commit_changes(session)
            self.attestation.commit_changes(session)

            for item in self.attestation.evidence:
                item.commit_changes(session)

            # If the previous attestation passed verification and is not the first authenticated attestation
            # received after boot, then delete...

            att = self.attestation
            prev_att = self.attestation.previous_attestation
            prev_prev_att = prev_att.previous_authenticated_attestation if prev_att else None

            if (
                prev_att and prev_prev_att
                and att.evaluation == "pass" and prev_att.evaluation == "pass"
                and prev_att.system_info.boot_time == prev_prev_att.system_info.boot_time
            ):
                prev_att.delete()

    def verify_evidence(self):
        if not self.attestation.changes_valid:
            raise ValueError("attestation cannot be verified as it has pending changes with errors")

        if self.attestation.stage == "verification_complete":
            raise ValueError("attestation has already undergone verification")

        engines_to_activate = set()

        for item in self.attestation.evidence:
            engines_to_activate.update(self.get_evidence_evaluators(item.evidence_type))

        for engine in engines_to_activate:
            engine(self.attestation).verify_evidence()

            if self.attestation.get_errors():
                return self

        self._commit_verification_results()

        return self

    @property
    def attestation(self):
        return self._attestation