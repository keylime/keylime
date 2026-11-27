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
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version
from typing import Any, Dict, List, Optional, Tuple, get_args

from keylime.claims.base import EvaluationResult, KeylimeClaimsError, PolicySource, Status

# Profile tag pinned to ear 0.6.0 (the crate trustee consumes); the claim
# spellings and the eat_nonce output form follow draft-ietf-rats-ear-06,
# the current draft generation.
EAR_PROFILE = "tag:ietf.org,2026:rats/ear#04"
DEFAULT_VERIFIER_DEVELOPER = "https://keylime.dev"

_ALLOWED_STATUSES = frozenset(get_args(Status))
_ALLOWED_POLICY_SOURCES = frozenset(get_args(PolicySource))

_NONCE_MIN_BYTES = 16
_NONCE_MAX_BYTES = 64

# Either base64 alphabet (RFC 4648 sections 4 and 5) with optional
# padding: relying parties mint both (trustee's KBS uses padded standard
# base64, RFC 9711 clients use unpadded base64url).
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
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
    ttl, canonical_nonce = _validate_inputs(results, nonce, ttl, jti, iat=iat, iss=iss)

    if any(r.status == "error" for r in results):
        return None

    if iat is None:
        iat = int(time.time())

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
        submod: Dict[str, Any] = {
            # Unreachable for "error" (short-circuits above); defensive.
            "ear_status": "affirming" if r.status == "pass" else "contraindicated",
            "ear_appraisal_policy_ids": [r.policy],
            # Shared by reference with results[*].claims.
            "ear_attester_claims": r.claims,
            "keylime_evidence_type": r.evidence_type,
            "keylime_policy_source": r.policy_source,
            "keylime_failures": [_entry_to_dict(f) for f in r.failures],
            "keylime_trust_anchor_fingerprints": r.trust_anchor_fingerprints,
            "keylime_evidence_nonce": r.evidence_nonce,
        }
        # Omitted — not null — while uncomputed: the draft makes the vector
        # conditional, and typed consumers (ear 0.6.0) reject a JSON null
        # for this registered claim name.
        if r.trustworthiness is not None:
            submod["ear_trustworthiness_vector"] = r.trustworthiness
        submods[r.evaluation_id] = submod

    return {
        "eat_profile": EAR_PROFILE,
        "iss": iss,
        "iat": iat,
        "nbf": iat,
        "exp": iat + ttl,
        "jti": jti,
        "eat_nonce": canonical_nonce,
        "ear_verifier_id": {"developer": verifier_developer, "build": verifier_build},
        "ear_status": ear_status,
        "submods": submods,
    }


def _validate_inputs(
    results: List[EvaluationResult],
    nonce: str,
    ttl: int,
    jti: Optional[str],
    iat: Optional[int] = None,
    iss: Optional[str] = None,
) -> Tuple[int, str]:
    """Run the input guards in order (before the error short-circuit, so
    input errors surface even when an evaluation also errored); return
    the coerced ttl and the canonical nonce encoding."""
    if not results:
        raise KeylimeClaimsError("cannot assemble EAR claims for an empty result list")

    # The submods key is client-chosen and lands in the signed token —
    # bound it like every other client-influenced string.
    for r in results:
        eid = r.evaluation_id
        if not isinstance(eid, str) or not eid or len(eid) > 128:
            raise KeylimeClaimsError(f"evaluation_id must be a non-empty string of at most 128 characters, got {eid!r}")
        # A misspelled status would skip the error veto and get signed as a fail.
        if r.status not in _ALLOWED_STATUSES:
            raise KeylimeClaimsError(
                f"result {eid!r} has invalid status {r.status!r}; expected one of {sorted(_ALLOWED_STATUSES)}"
            )
        if r.policy_source not in _ALLOWED_POLICY_SOURCES:
            raise KeylimeClaimsError(
                f"result {eid!r} has invalid policy_source {r.policy_source!r}; "
                f"expected one of {sorted(_ALLOWED_POLICY_SOURCES)}"
            )
        # policy lands in ear_appraisal_policy_ids inside the signed token:
        # typed consumers reject a null and an unbounded string bloats it —
        # bound it like every other client-influenced field.
        if not isinstance(r.policy, str) or not r.policy or len(r.policy) > 256:
            raise KeylimeClaimsError(
                f"result {eid!r} policy must be a non-empty string of at most 256 characters, got {r.policy!r}"
            )

    ids = [r.evaluation_id for r in results]
    duplicates = {evaluation_id for evaluation_id, count in Counter(ids).items() if count > 1}
    if duplicates:
        raise KeylimeClaimsError(f"duplicate evaluation ids in results: {sorted(duplicates)}")

    canonical_nonce = _validate_nonce(nonce)

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
        # Reject bools (int subclasses that would become 1970 timestamps),
        # floats and numeric strings — same loud-failure discipline as ttl.
        if isinstance(iat, bool) or not isinstance(iat, int):
            raise KeylimeClaimsError(f"iat must be an integer, got {iat!r}")

    if jti is not None:
        try:
            uuid.UUID(str(jti))
        except (ValueError, AttributeError, TypeError) as e:
            raise KeylimeClaimsError(f"jti must be a UUID, got {jti!r}") from e

    return ttl_int, canonical_nonce


def _validate_nonce(nonce: str) -> str:
    """Enforce the nonce contract; return the canonical encoding.

    Either base64 alphabet is accepted (relying parties mint both:
    trustee's KBS uses padded standard base64, RFC 9711 clients use
    unpadded base64url). The string is decoded strictly — rejecting
    non-canonical lengths, malformed padding and non-canonical trailing
    bits — and length-checked in decoded bytes. eat_nonce carries the
    canonical unpadded base64url re-encoding, the form mandated by
    draft-ietf-rats-ear-06 section 3 and decoded by typed EAR consumers
    (ear 0.6.0); a relying party compares decoded bytes, not the
    submitted string.
    """
    if not isinstance(nonce, str) or not nonce:
        raise KeylimeClaimsError("nonce must be a non-empty base64 or base64url string")
    if _BASE64_RE.fullmatch(nonce) is None and _BASE64URL_RE.fullmatch(nonce) is None:
        raise KeylimeClaimsError("nonce is not valid base64 or base64url")
    urlsafe = "-" in nonce or "_" in nonce
    padded = nonce + "=" * (-len(nonce) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_" if urlsafe else None, validate=True)
    except (binascii.Error, ValueError) as e:
        raise KeylimeClaimsError("nonce is not valid base64 or base64url") from e
    if len(decoded) < _NONCE_MIN_BYTES or len(decoded) > _NONCE_MAX_BYTES:
        raise KeylimeClaimsError(
            f"nonce must decode to between {_NONCE_MIN_BYTES} and {_NONCE_MAX_BYTES} bytes, got {len(decoded)}"
        )
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    stripped = nonce.rstrip("=")
    if stripped != canonical and stripped != base64.b64encode(decoded).rstrip(b"=").decode("ascii"):
        # Decodes fine but re-encodes differently: non-canonical
        # trailing bits (RFC 4648 section 3.5), which consumers like
        # ear 0.6.0 reject on re-encode.
        raise KeylimeClaimsError("nonce is not canonically encoded; re-encode it canonically (base64url, unpadded)")
    return canonical


def _entry_to_dict(entry: Any) -> Dict[str, Any]:
    # Emit null context for schema stability.
    return {"type": entry.type, "message": entry.message, "context": entry.context}
