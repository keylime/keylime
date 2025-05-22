from abc import ABC, abstractmethod
from keylime.verification.base.verification_engine_meta import VerificationEngineMeta

class VerificationEngine(ABC, metaclass=VerificationEngineMeta):
    @classmethod
    @abstractmethod
    def register_callbacks(cls) -> None:
        pass

    def __init__(self, attestation):
        self._attestation = attestation

    @property
    def attestation(self):
        return self._attestation

    @property
    def agent(self):
        return self.attestation.agent

    @property
    def agent_id(self):
        return self.attestation.agent_id

    @property
    def index(self):
        return self.attestation.index

    @property
    def stage(self):
        return self.attestation.stage

    @property
    def evaluation(self):
        return self.attestation.evaluation

    @evaluation.setter
    def evaluation(self, evaluation):
        self.attestation.evaluation = evaluation

    @property
    def failure_reason(self):
        return self.attestation.failure_reason

    @failure_reason.setter
    def failure_reason(self, failure_reason):
        self.attestation.failure_reason = failure_reason

    @property
    def previous_attestation(self):
        return self.attestation.previous_attestation

    @property
    def previous_authenticated_attestation(self):
        return self.attestation.previous_authenticated_attestation

    @property
    def previous_passed_attestation(self):
        return self.attestation.previous_passed_attestation