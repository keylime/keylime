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

import copy
from typing import Any, Dict, Optional, Sequence

from keylime import keylime_logging
from keylime.claims.base import (
    EvaluationResult,
    KeylimeClaimsError,
    OutputFormat,
    RenderedResponse,
    Renderer,
    Signer,
    VerificationOutput,
)
from keylime.claims.registry import register_output_format

logger = keylime_logging.init_logging("claims.renderers.jsonapi")


@register_output_format
class JsonApiRenderer(Renderer):
    format = OutputFormat.JSONAPI

    def render(self, output: VerificationOutput, signer: Signer | None) -> RenderedResponse:
        token = None
        if output.ear_claims is not None:  # infra error -> no token, null result
            # Issuance invariants shared with the raw-JWT renderer — keep
            # in lockstep: reuse-before-sign, deep copy before the signer,
            # signer failures as KeylimeClaimsError, write-once ear_token.
            if output.ear_token is not None:
                logger.info("EAR token reused: jti=%s", output.ear_claims["jti"])
                token = output.ear_token
            else:
                if signer is None:
                    raise KeylimeClaimsError(
                        "JSON:API output requires a signer when claims were assembled; none configured"
                    )
                try:
                    token = signer(copy.deepcopy(output.ear_claims))
                except KeylimeClaimsError:
                    raise
                except Exception as e:
                    raise KeylimeClaimsError("EAR token signing failed") from e
                if not isinstance(token, str) or not token:
                    # A None/empty return would be indistinguishable
                    # from the infra-error path (null attestation_result).
                    raise KeylimeClaimsError("the signer did not return a token string")
                output.ear_token = token  # write-once (audit)
                logger.info("EAR token issued: jti=%s", output.ear_claims["jti"])
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
