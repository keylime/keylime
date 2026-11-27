"""Shared token-issuance invariants for the renderers.

Both renderers sign the same claims under the same rules: reuse-before-
sign, deep copy before the signer, signer failures wrapped as
KeylimeClaimsError, write-once ear_token. Living here once, the two
output paths cannot drift apart.
"""

from __future__ import annotations

import copy
from typing import Optional

from keylime import keylime_logging
from keylime.claims.base import KeylimeClaimsError, Signer, VerificationOutput

logger = keylime_logging.init_logging("claims.renderers.issuance")


def issue_token(output: VerificationOutput, signer: Optional[Signer], format_name: str) -> str:
    """Return the signed EAR token for ``output``, issuing it if needed.

    Raises KeylimeClaimsError when ``output.ear_claims`` is None (an
    infra-error output must never reach signing), when no signer is
    configured, or when the signer fails; never caches a failed or
    non-string result.
    """
    claims = output.ear_claims
    if claims is None:
        raise KeylimeClaimsError(f"{format_name} output requires assembled EAR claims; none present")
    if output.ear_token is not None:
        logger.info("EAR token reused: jti=%s", claims["jti"])
        return output.ear_token
    if signer is None:
        raise KeylimeClaimsError(f"{format_name} output requires a signer when claims were assembled; none configured")
    try:
        token = signer(copy.deepcopy(claims))
    except KeylimeClaimsError:
        raise
    except Exception as e:
        raise KeylimeClaimsError("EAR token signing failed") from e
    if not isinstance(token, str) or not token:
        # A None/empty return must not be cached as the token (it would
        # be indistinguishable from the infra-error path).
        raise KeylimeClaimsError("the signer did not return a token string")
    output.ear_token = token  # write-once (audit)
    logger.info("EAR token issued: jti=%s", claims["jti"])
    return token
