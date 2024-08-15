from enum import Enum
from typing import Any

class AttestationStatusEnum(Enum):
    WAITING = "WAITING" # Attestation resource has been created but verifier is waiting to receive quote
    RECEIVED = "RECEIVED" # Valid quote has been received but we are awaiting a verification outcome
    VERIFIED = "VERIFIED" # Quote was successfully authenticated and verified against policy
    FAILED = "FAILED" # Quote could not be authenticated or failed verification against policy

    def to_json(self):
        return self.value
