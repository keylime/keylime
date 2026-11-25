"""Claims pipeline: verification facts -> nested claims -> response payloads.

Stage 1 (build) translates per-evidence-type facts into nested claims and
assembles the format-agnostic EAR claims. Stage 2 (render) dispatches
through the renderer registry and applies the injected signer. This
package never verifies evidence and never parses HTTP headers.
"""

from keylime.claims.base import (  # noqa: F401
    EvaluatedEvidence,
    EvaluationResult,
    FailureEntry,
    KeylimeClaimsError,
    PolicySource,
    RenderedResponse,
    Signer,
    Status,
    VerificationOutput,
)
from keylime.claims.failures import normalize_failure  # noqa: F401
from keylime.claims.registry import (  # noqa: F401
    register_evidence_type,
    register_output_format,
    renderer_registry,
    translator_registry,
)
