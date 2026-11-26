"""Claims pipeline: verification facts -> nested claims -> response payloads.

Public API:
    build_verification_output(items, nonce=..., iss=..., ...) -> VerificationOutput
    render_response(output, output_format=..., signer=...) -> RenderedResponse
    OutputFormat
    assemble_evaluation_results(items) -> [EvaluationResult]  (deeper entry point)
    plus the input/output record types and KeylimeClaimsError.

Stage 1 (build) translates per-evidence-type facts into nested claims and
assembles the format-agnostic EAR claims. Stage 2 (render) dispatches
through the renderer registry and applies the injected signer. This
package never verifies evidence and never parses HTTP headers.
"""

# Import the strategy packages so their registrations run at import time.
# This is the explicit registration point for translators and renderers.
from keylime.claims import renderers  # noqa: F401,E402  (registration side effect)
from keylime.claims import translators  # noqa: F401,E402  (registration side effect)
from keylime.claims.base import (  # noqa: F401
    EvaluatedEvidence,
    EvaluationResult,
    FailureEntry,
    KeylimeClaimsError,
    OutputFormat,
    PolicySource,
    RenderedResponse,
    Signer,
    Status,
    VerificationOutput,
)
from keylime.claims.pipeline import (  # noqa: F401
    assemble_evaluation_results,
    build_verification_output,
)
from keylime.claims.render import render_response  # noqa: F401
