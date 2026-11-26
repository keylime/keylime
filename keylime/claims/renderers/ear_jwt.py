"""Renderer for the raw EAR JWT output format — the response body IS the
signed token.

Per the content-negotiation rules of the verification API: a client
requesting the EAT media type decodes the JWT directly. Infrastructure
errors produce a Problem Details document (RFC 9457) instead, because
there is no token to return — currently a minimal stub, see
``_problem_details``.
"""

from __future__ import annotations

import copy

from keylime import keylime_logging
from keylime.claims.base import (
    KeylimeClaimsError,
    OutputFormat,
    RenderedResponse,
    Renderer,
    Signer,
    VerificationOutput,
)
from keylime.claims.ear import EAR_PROFILE
from keylime.claims.registry import register_output_format

logger = keylime_logging.init_logging("claims.renderers.ear_jwt")


@register_output_format
class EarJwtRenderer(Renderer):
    format = OutputFormat.EAR_JWT

    def render(self, output: VerificationOutput, signer: Signer | None) -> RenderedResponse:
        if output.ear_claims is None:
            return self._problem_details(output)  # infra error -> no token

        # Issuance invariants shared with the JSON:API renderer — keep
        # in lockstep: reuse-before-sign, deep copy before the signer,
        # signer failures as KeylimeClaimsError, write-once ear_token.
        if output.ear_token is not None:
            logger.info("EAR token reused: jti=%s", output.ear_claims["jti"])
            token = output.ear_token
        else:
            if signer is None:
                raise KeylimeClaimsError("EAR_JWT output requires a signer; none configured")
            try:
                token = signer(copy.deepcopy(output.ear_claims))
            except KeylimeClaimsError:
                raise
            except Exception as e:
                raise KeylimeClaimsError("EAR token signing failed") from e
            if not isinstance(token, str) or not token:
                # A None/empty return must not be cached as the token
                # (it would be indistinguishable from the infra-error
                # path in the JSON:API body).
                raise KeylimeClaimsError("the signer did not return a token string")
            output.ear_token = token  # write-once (audit)
            logger.info("EAR token issued: jti=%s", output.ear_claims["jti"])
        return RenderedResponse(
            content_type=f'{self.format.value}; eat_profile="{EAR_PROFILE}"',
            body=token,
            headers={"Vary": "Accept"},
        )

    # Per the plan: the verifier reports an upstream/pipeline failure, so
    # the Problem Details response is a 502 (Bad Gateway), not a 500.
    _PROBLEM_STATUS = 502

    @staticmethod
    def _problem_details(output: VerificationOutput) -> RenderedResponse:
        # TODO: full RFC 9457 document built from output.results
        #   (status "error" + failure details). Stub returns a minimal body.
        #   ``output`` is threaded for that pending implementation.
        # pylint: disable=unused-argument
        return RenderedResponse(
            content_type="application/problem+json",
            # The body's "status" member is the RFC 9457 self-description
            # (survives body-only consumption); RenderedResponse.status is
            # the HTTP hint — the body alone cannot tell success from
            # failure, so the response status must never be left to derive
            # a 2xx for an infra error.
            body={"title": "Attestation evaluation error", "status": EarJwtRenderer._PROBLEM_STATUS},
            headers={"Vary": "Accept"},
            status=EarJwtRenderer._PROBLEM_STATUS,
        )
