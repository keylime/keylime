"""Render a VerificationOutput into a response payload.

Dispatches through the renderer registry (keyed by OutputFormat); format
and signer meet here, since only format-specific rendering needs the
signed token. Both args are EXPLICIT — no defaults. Content negotiation
(and any "no Accept header -> JSON:API" default) is the caller's job; a
controller that forgets to negotiate must fail loudly, not silently
render JSON:API.
"""

from __future__ import annotations

from keylime.claims.base import OutputFormat, RenderedResponse, Signer, VerificationOutput
from keylime.claims.registry import renderer_registry


def render_response(
    output: VerificationOutput, *, output_format: OutputFormat, signer: Signer | None
) -> RenderedResponse:
    """Look up the renderer for ``output_format`` and delegate."""
    renderer_cls = renderer_registry.get(output_format)  # unknown -> KeylimeClaimsError
    return renderer_cls().render(output, signer)
