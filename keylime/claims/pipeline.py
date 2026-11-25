"""Orchestration: already-evaluated items -> evaluation results + EAR claims.

Only BUILDS: items arrive evaluated and classified by the caller; signing
and format selection happen at render time. No I/O or config reads —
all ambient values are parameters.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from keylime import keylime_logging
from keylime.claims.base import ClaimsTranslator, EvaluatedEvidence, EvaluationResult, VerificationOutput
from keylime.claims.ear import assemble_ear_claims
from keylime.claims.failures import normalize_failure
from keylime.claims.registry import translator_registry

logger = keylime_logging.init_logging("claims.pipeline")


def build_verification_output(
    items: List[EvaluatedEvidence],
    *,
    nonce: str,
    iss: str,
    jti: str | None = None,
    iat: int | None = None,
    ttl: int = 300,
) -> VerificationOutput:
    """Build the format-agnostic output of one verification request — stage 1
    of the public two-call API (build, then render).

    Translates each evaluated item's facts into claims and assembles the
    EAR claims dict (the unsigned token payload every format needs; None
    if any evaluation errored, so no token may be issued). ear_token
    stays None until a renderer signs it. ``items`` holds one record per
    request EVALUATION, not per evidence; ``nonce`` is the REQUEST-level
    nonce; ``jti``/``iat`` let callers and tests pin identity and time;
    exp = iat + ttl.

    The caller must have initialized the measured-boot parsers before
    evaluating TPM evidence (naturally true in a verifier process).
    """
    results = assemble_evaluation_results(items)  # stage A
    ear_claims = assemble_ear_claims(results, nonce=nonce, iss=iss, jti=jti, iat=iat, ttl=ttl)  # stage B
    # ear_token stays None until a renderer signs it (write-once)
    return VerificationOutput(results=results, ear_claims=ear_claims, ear_token=None)


def assemble_evaluation_results(items: List[EvaluatedEvidence]) -> List[EvaluationResult]:
    """Turn each evaluated item into an EvaluationResult, in input order.

    The per-item half of build_verification_output, and the only place
    the pipeline branches on evidence type (registry lookup; unknown
    type raises). Produces the neutral record every output path
    consumes: translated claims (shared by reference), normalized
    failures, verdict and policy metadata. Translator exceptions
    propagate, never swallowed.
    """
    results: List[EvaluationResult] = []
    instances: Dict[str, ClaimsTranslator] = {}  # translators are stateless — one per type
    for item in items:
        if item.evidence_type not in instances:
            instances[item.evidence_type] = translator_registry.get(item.evidence_type)()
        claims = instances[item.evidence_type].translate(item)
        failures = normalize_failure(item.failure)
        results.append(
            EvaluationResult(
                evaluation_id=item.evaluation_id,
                evidence_id=item.evidence_id,
                evidence_type=item.evidence_type,
                status=item.status,
                claims=claims,
                failures=failures,
                policy=item.policy_name,
                policy_source=item.policy_source,
                policy_fingerprint=compute_policy_fingerprint(item.policies),
            )
        )
    return results


def compute_policy_fingerprint(policies: Any) -> str | None:
    """Fingerprint the CONTENT of a resolved policy as "sha256:<hex>".

    Emitted as keylime_policy_fingerprint, it binds the verdict to what
    was actually evaluated — the policy NAME only names the source, so
    identical ids may reflect different policies. Canonical JSON makes
    semantically identical dicts fingerprint identically; None when no
    policy content was provided.
    """
    if not policies:
        return None
    try:
        # No default=str: a non-JSON-serializable value must hit the
        # warn-and-None path below, not be repr()'d into the canonical
        # form — repr ordering (e.g. sets) varies per process, which
        # would silently change the fingerprint across restarts.
        canonical = json.dumps(policies, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        logger.warning("Could not serialize the resolved policy for fingerprinting: %s", e)
        return None
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
