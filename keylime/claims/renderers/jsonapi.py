"""JSON:API renderer (skeleton — envelope internals not yet implemented).

The envelope wraps BOTH a readable copy (results[], for operators, CI and
debugging — never a trust surface) and the signed token
(attestation_result — the artifact relying parties verify). Same claims
dicts as the EAR path, by reference. Until the envelope is implemented,
``_envelope`` returns a minimal placeholder marked with TODOs; the
renderer itself is live and registered so the dispatch path is exercised
end-to-end (and ``body`` never violates its type).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence

from keylime.claims.base import (
    EvaluationResult,
    OutputFormat,
    RenderedResponse,
    Renderer,
    Signer,
    VerificationOutput,
)
from keylime.claims.registry import register_output_format
from keylime.claims.renderers.issuance import issue_token


@register_output_format
class JsonApiRenderer(Renderer):
    format = OutputFormat.JSONAPI

    def render(self, output: VerificationOutput, signer: Signer | None) -> RenderedResponse:
        token = None
        if output.ear_claims is not None:  # infra error -> no token, null result
            token = issue_token(output, signer, format_name=self.format.name)
        body = self._envelope(output.results, attestation_result=token)
        # No explicit status on the evaluation-error path either: per the
        # plan, JSON:API evaluation-level errors are HTTP 200 with
        # attestation_result null — the request is valid, the verifier
        # cannot evaluate (some of) it.
        return RenderedResponse(
            content_type=self.format.value,
            body=body,
            headers={"Vary": "Accept"},
        )

    @staticmethod
    def _envelope(results: Sequence[EvaluationResult], *, attestation_result: Optional[str]) -> Dict[str, Any]:
        # TODO: full envelope — results array with all fields
        #   (forward-compatible nulls), same claims objects as the token
        #   submods use. ``results`` is threaded for that pending
        #   implementation.
        # pylint: disable=unused-argument
        return {
            "data": {
                "type": "evidence-verification-result",
                "attributes": {
                    "results": None,  # TODO: populate per result
                    "attestation_result": attestation_result,
                },
            },
        }
