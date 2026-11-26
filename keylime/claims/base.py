"""Contracts between the evaluation pipeline (the caller) and all output paths.

This package transforms verification state — keylime-internal failure
objects, evidence blocks, verdicts — into a readable, JSON-serializable
claim structure that can be signed and rendered. The value objects and
two strategy interfaces (translator, renderer) below are that contract;
no behavior here touches verification state itself.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, ClassVar, Dict, List, Literal, Mapping, Optional, Sequence

Status = Literal["pass", "fail", "error"]
PolicySource = Literal["inline", "registered"]
Signer = Callable[[Dict[str, Any]], str]
"""Signs the EAR claims dict and returns the serialized token string.
Injected by the caller; this package never imports a JWT/CBOR library."""


class KeylimeClaimsError(Exception):
    """Base error for the claims pipeline: bad inputs, unknown evidence
    types or formats, missing signer."""


@dataclass(frozen=True)
class FailureEntry:
    """The external form of a failure, for signed output — used instead
    of keylime's Failure because that type carries internal event ids
    and unbounded, attester-influenced context, neither of which may
    appear in a token verbatim."""

    type: str
    message: str
    context: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class EvaluatedEvidence:
    """Input record: one evidence/policy pair, already evaluated and
    classified by the caller — this package never verifies.

    The caller owns the try/except around verification: a raised exception
    maps to status "error" (infrastructure failure, no token), a returned
    Failure with events to "fail", a clean return to "pass". An unavailable
    verifier dependency must never surface as a signed negative verdict.
    """

    evaluation_id: str
    """Submods key; unique per EVALUATION (not per evidence) — the same
    evidence may be evaluated against several policies."""

    evidence_id: str
    """The request's evidences map key (e.g. "default")."""

    evidence_type: str
    """Coarse claims category ("tpm", "tee-snp"); the caller normalizes the
    request's granular evidence types onto it."""

    evidence: Mapping[str, Any]
    """The request's evidence data block (quote, logs, ...)."""

    policies: Mapping[str, Any]
    """Resolved policies (parsed)."""

    policy_name: str
    """Policy source label (e.g. "tpm:inline")."""

    policy_source: PolicySource
    """"inline" | "registered"."""

    failure: Any
    """The verification Failure object (kept opaque)."""

    status: Status
    """Verdict classified by the evaluator."""


@dataclass(frozen=True)
class EvaluationResult:
    """Output record: the verdict plus the translated claims, consumed by
    every output path. ``claims`` and ``failures`` are shared BY REFERENCE
    between the token payload and the readable body — do not mutate after
    construction."""

    evaluation_id: str
    evidence_id: str
    evidence_type: str
    status: Status
    claims: Mapping[str, Any]
    failures: Sequence[FailureEntry]
    policy: str
    policy_source: PolicySource
    # Forward-compatible fields for later development stages, present from
    # day one so the wire schema never changes shape:
    policy_uuid: Optional[str] = None
    policy_revision: Optional[int] = None
    resolved_sub_policies: Optional[Dict[str, Any]] = None
    trustworthiness: Optional[Dict[str, Any]] = None
    trust_anchor_fingerprints: Optional[List[str]] = None
    # Phase 3 per-submod keylime_evidence_nonce; threads from the evidence.
    evidence_nonce: Optional[str] = None


@dataclass
class VerificationOutput:
    """Everything this package produces; rendering finalizes it.

    ``ear_claims`` is None iff any result has status "error". ``ear_token``
    is write-once, set by a renderer when it signs — the only field that
    changes after build, hence the class is not frozen.
    """

    results: list[EvaluationResult]
    ear_claims: Optional[Dict[str, Any]]
    ear_token: Optional[str] = None


class OutputFormat(Enum):
    """Response media types; the web layer maps the Accept header to a member."""

    JSONAPI = "application/vnd.api+json"
    EAR_JWT = "application/eat+jwt"


@dataclass(frozen=True)
class RenderedResponse:
    """A renderer's result, mapped by the caller to the HTTP response.

    ``body`` is a raw token string or a JSON document dict; dict bodies are
    shared with results[*].claims — treat as read-only.
    """

    content_type: str
    body: "str | Dict[str, Any]"
    headers: Dict[str, str] = field(default_factory=dict)
    """Every renderer sets {"Vary": "Accept"}."""

    status: Optional[int] = None
    """Forward-compatible HTTP status hint. None means "derive it from
    the body" (2xx for a token or envelope, 4xx/5xx for a Problem
    Details document). The error path will set it before the web layer
    lands, so renderers never grow an out-of-band status channel."""


class ClaimsTranslator(ABC):
    """Turns one evidence type's verification facts into claims.

    Each attestation source (TPM quote, TEE report, ...) gets its own
    subclass, registered under a coarse evidence-type key. The claims it
    produces are plain, verdict-independent facts restated from the
    already-evaluated evidence — never new judgments — and the same dict
    feeds both the signed token and the readable response body.
    """

    evidence_type: ClassVar[str]

    @abstractmethod
    def translate(self, item: EvaluatedEvidence) -> Dict[str, Any]:
        """Return nested claims for this evidence type."""


class Renderer(ABC):
    """Turns a VerificationOutput into the payload of one output format.

    Each response media type (raw EAR JWT, JSON:API, ...) gets its own
    subclass, registered under the negotiated OutputFormat key. The
    renderer applies the injected signer where the format needs a
    signed token; format selection itself is the caller's job.
    """

    format: ClassVar[OutputFormat]

    @abstractmethod
    def render(self, output: VerificationOutput, signer: Optional[Signer]) -> RenderedResponse:
        """Render the verification output in this format."""
