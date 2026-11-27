"""Renderer for the raw EAR JWT output format — the response body IS the
signed token.

Per the content-negotiation rules of the verification API: a client
requesting the EAT media type decodes the JWT directly. Infrastructure
errors produce a Problem Details document (RFC 9457) instead, because
there is no token to return — currently a minimal stub, see
``_problem_details``.
"""

from __future__ import annotations

from keylime.claims.base import (
    OutputFormat,
    RenderedResponse,
    Renderer,
    Signer,
    VerificationOutput,
)
from keylime.claims.ear import EAR_PROFILE
from keylime.claims.registry import register_output_format
from keylime.claims.renderers.issuance import issue_token

# Per the plan: the verifier reports an upstream/pipeline failure, so
# the Problem Details response is a 502 (Bad Gateway), not a 500.
_PROBLEM_STATUS = 502


@register_output_format
class EarJwtRenderer(Renderer):
    format = OutputFormat.EAR_JWT

    def render(self, output: VerificationOutput, signer: Signer | None) -> RenderedResponse:
        if output.ear_claims is None:
            return self._problem_details(output)  # infra error -> no token

        token = issue_token(output, signer, format_name=self.format.name)
        return RenderedResponse(
            content_type=f'{self.format.value}; eat_profile="{EAR_PROFILE}"',
            body=token,
            headers={"Vary": "Accept"},
        )

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
            body={"title": "Attestation evaluation error", "status": _PROBLEM_STATUS},
            headers={"Vary": "Accept"},
            status=_PROBLEM_STATUS,
        )
