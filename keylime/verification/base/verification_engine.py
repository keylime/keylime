from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from keylime.verification.base.verification_engine_meta import VerificationEngineMeta

if TYPE_CHECKING:
    from keylime.models.verifier import Attestation


class VerificationEngine(ABC, metaclass=VerificationEngineMeta):
    @classmethod
    @abstractmethod
    def register_callbacks(cls) -> None:
        pass

    def __init__(self, attestation: "Attestation") -> None:
        self._attestation = attestation

    @property
    def attestation(self) -> "Attestation":
        return self._attestation

    @property
    def agent(self) -> Any:
        return self.attestation.agent

    @property
    def agent_id(self) -> str:
        return self.attestation.agent_id  # type: ignore[no-any-return, attr-defined]

    @property
    def index(self) -> int:
        return self.attestation.index  # type: ignore[no-any-return]

    @property
    def stage(self) -> str:
        return self.attestation.stage  # type: ignore[no-any-return]

    @property
    def evaluation(self) -> str | None:
        return self.attestation.evaluation  # type: ignore[no-any-return]

    @evaluation.setter
    def evaluation(self, evaluation: str | None) -> None:
        self.attestation.evaluation = evaluation

    @property
    def failure_reason(self) -> str | None:
        return self.attestation.failure_reason  # type: ignore[no-any-return, attr-defined]

    @failure_reason.setter
    def failure_reason(self, failure_reason: str | None) -> None:
        self.attestation.failure_reason = failure_reason  # type: ignore[attr-defined]

    @property
    def previous_attestation(self) -> "Attestation | None":
        return self.attestation.previous_attestation  # type: ignore[no-any-return]

    @property
    def previous_authenticated_attestation(self) -> "Attestation | None":
        return self.attestation.previous_authenticated_attestation  # type: ignore[no-any-return]

    @property
    def previous_passed_attestation(self) -> "Attestation | None":
        return self.attestation.previous_passed_attestation  # type: ignore[no-any-return]
