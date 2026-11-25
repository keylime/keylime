"""Assembly of the EAT Attestation Results (EAR) claims dict.

Assembles the claims structure defined by the IETF RATS EAR draft
(draft-ietf-rats-ear) as a format-agnostic dict consumed by every output
format: the raw JWT format signs it, the JSON:API format embeds the
signed version. Does NOT sign; all ambient values are parameters.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
import uuid
from collections import Counter
from importlib.metadata import PackageNotFoundError, version as _package_version
from typing import Any, Dict, List, Optional

from keylime.claims.base import EvaluationResult, KeylimeClaimsError

EAR_PROFILE = "tag:ietf.org,2026:rats/ear#05"
DEFAULT_VERIFIER_DEVELOPER = "https://keylime.dev"

_NONCE_MIN_BYTES = 16
_NONCE_MAX_BYTES = 64

# Strict base64url alphabet (RFC 4648 section 5) with optional padding.
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]*={0,2}")


def assemble_ear_claims(
    results: List[EvaluationResult],
    *,
    nonce: str,
    iss: str,
    jti: Optional[str] = None,
    iat: Optional[int] = None,
    ttl: int = 300,
    verifier_developer: str = DEFAULT_VERIFIER_DEVELOPER,
    verifier_build: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return the EAR claims dict, or None if any result has status "error".

    Worst-case aggregation: all pass -> "affirming"; any fail, no error
    -> "contraindicated"; any error -> None (no token is issued).
    """
    ttl = _validate_inputs(results, nonce, ttl, jti, iat=iat, iss=iss)

    if any(r.status == "error" for r in results):
        return None

    if iat is None:
        iat = int(time.time())
    else:
        # Truncate toward zero (EAT forbids fractional times).
        iat = int(iat)

    if jti is None:
        jti = str(uuid.uuid4())
    else:
        # Canonical lowercase-hyphenated form.
        jti = str(uuid.UUID(str(jti)))

    if verifier_build is None:
        # TODO: reports the INSTALLED package version, which can differ
        #   from the running code in a source checkout.
        try:
            verifier_build = _package_version("keylime")
        except PackageNotFoundError:
            verifier_build = "unknown"

    if all(r.status == "pass" for r in results):
        ear_status = "affirming"
    else:
        ear_status = "contraindicated"

    submods: Dict[str, Any] = {}
    for r in results:
        submods[r.evaluation_id] = {
            # Unreachable for "error" (short-circuits above); defensive.
            "ear_status": "affirming" if r.status == "pass" else "contraindicated",
            "ear_appraisal_policy_ids": [r.policy],
            # Shared by reference with results[*].claims.
            "ear_attester_claims": r.claims,
            "keylime_evidence_type": r.evidence_type,
            "keylime_policy_source": r.policy_source,
            "keylime_policy_fingerprint": r.policy_fingerprint,
            "keylime_failures": [_entry_to_dict(f) for f in r.failures],
            # Future slots (trustworthiness, trust anchors) — not added yet.
        }

    return {
        "eat_profile": EAR_PROFILE,
        "iss": iss,
        "iat": iat,
        "nbf": iat,
        "exp": iat + ttl,
        "jti": jti,
        "eat_nonce": nonce,
        "ear_verifier_id": {"developer": verifier_developer, "build": verifier_build},
        "ear_status": ear_status,
        "submods": submods,
    }


def _validate_inputs(
    results: List[EvaluationResult], nonce: str, ttl: int, jti: Optional[str],
    iat: Optional[int] = None, iss: Optional[str] = None,
) -> int:
    """Run the input guards in order (before the error short-circuit, so
    input errors surface even when an evaluation also errored); return
    the coerced ttl."""
    if not results:
        raise KeylimeClaimsError("cannot assemble EAR claims for an empty result list")

    # The submods key is client-chosen and lands in the signed token —
    # bound it like every other client-influenced string.
    for r in results:
        eid = r.evaluation_id
        if not isinstance(eid, str) or not eid or len(eid) > 128:
            raise KeylimeClaimsError(
                f"evaluation_id must be a non-empty string of at most 128 characters, got {eid!r}"
            )

    ids = [r.evaluation_id for r in results]
    duplicates = {evaluation_id for evaluation_id, count in Counter(ids).items() if count > 1}
    if duplicates:
        raise KeylimeClaimsError(f"duplicate evaluation ids in results: {sorted(duplicates)}")

    _validate_nonce(nonce)

    if not isinstance(iss, str) or not iss:
        raise KeylimeClaimsError(f"iss must be a non-empty string, got {iss!r}")

    try:
        ttl_int = int(ttl)
    except (TypeError, ValueError, ArithmeticError) as e:
        # ArithmeticError: int(float("inf")) overflows rather than
        # raising ValueError.
        raise KeylimeClaimsError(f"ttl must be a positive integer, got {ttl!r}") from e
    if ttl_int <= 0:
        raise KeylimeClaimsError(f"ttl must be a positive integer, got {ttl!r}")

    if iat is not None:
        # Reject bools (int subclasses that would become 1970 timestamps)
        # and numeric strings; only genuine numbers are truncated later.
        if isinstance(iat, bool) or not isinstance(iat, (int, float)):
            raise KeylimeClaimsError(f"iat must be an integer, got {iat!r}")
        try:
            int(iat)
        except (TypeError, ValueError, ArithmeticError) as e:
            raise KeylimeClaimsError(f"iat must be an integer, got {iat!r}") from e

    if jti is not None:
        try:
            uuid.UUID(str(jti))
        except (ValueError, AttributeError, TypeError) as e:
            raise KeylimeClaimsError(f"jti must be a UUID, got {jti!r}") from e

    return ttl_int


def _validate_nonce(nonce: str) -> None:
    """Enforce the nonce contract: base64url, 16-64 decoded bytes.

    The stdlib cannot check this directly — the decoder's altchars mode
    still accepts + and /, so the alphabet is checked by regex first —
    then the re-padded string is decoded strictly with the URL-safe
    alternative alphabet, which also rejects non-canonical lengths.
    """
    if not isinstance(nonce, str) or not nonce:
        raise KeylimeClaimsError("nonce must be a non-empty base64url string")
    if _BASE64URL_RE.fullmatch(nonce) is None:
        raise KeylimeClaimsError("nonce is not valid base64url")
    padded = nonce + "=" * (-len(nonce) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as e:
        raise KeylimeClaimsError("nonce is not valid base64url") from e
    if len(decoded) < _NONCE_MIN_BYTES or len(decoded) > _NONCE_MAX_BYTES:
        raise KeylimeClaimsError(
            f"nonce must decode to between {_NONCE_MIN_BYTES} and {_NONCE_MAX_BYTES} bytes, got {len(decoded)}"
        )


def _entry_to_dict(entry: Any) -> Dict[str, Any]:
    # Emit null context for schema stability.
    return {"type": entry.type, "message": entry.message, "context": entry.context}
