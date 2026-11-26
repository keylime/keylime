"""Orchestration: already-evaluated items -> evaluation results + EAR claims.

Only BUILDS: items arrive evaluated and classified by the caller; signing
and format selection happen at render time. No I/O or config reads —
all ambient values are parameters.
"""

from __future__ import annotations

from typing import Any, Dict, List

from keylime import keylime_logging
from keylime.claims.base import (
    ClaimsTranslator,
    EvaluatedEvidence,
    EvaluationResult,
    FailureEntry,
    KeylimeClaimsError,
    VerificationOutput,
)
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
    the pipeline branches on evidence type (registry lookup). Produces
    the neutral record every output path consumes: translated claims
    (shared by reference), normalized failures, verdict and policy
    metadata.

    An unknown evidence type or a translator failure degrades to a
    per-item error result (eval.unsupported_evidence_type /
    eval.translation_error) so the other evaluations in the same request
    complete — the caller cannot catch these, they raise after the
    hand-off. Caller-contract violations (inconsistent status, malformed
    inputs) still abort the whole build: those are bugs, not evaluation
    outcomes.
    """
    results: List[EvaluationResult] = []
    instances: Dict[str, ClaimsTranslator] = {}  # translators are stateless — one per type
    for item in items:
        _check_status_consistency(item, list(getattr(item.failure, "events", None) or []))
        if item.evidence_type not in instances:
            try:
                instances[item.evidence_type] = translator_registry.get(item.evidence_type)()
            except KeylimeClaimsError as e:
                results.append(_error_result(item, "eval.unsupported_evidence_type", e))
                continue
        try:
            claims = instances[item.evidence_type].translate(item)
        except KeylimeClaimsError as e:
            results.append(_error_result(item, "eval.translation_error", e))
            continue
        failures = normalize_failure(item.failure, item.evidence_type)
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
            )
        )
    return results


def _error_result(item: EvaluatedEvidence, failure_type: str, error: KeylimeClaimsError) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=item.evaluation_id,
        evidence_id=item.evidence_id,
        evidence_type=item.evidence_type,
        status="error",  # type: ignore[arg-type]
        claims={},
        failures=[FailureEntry(type=failure_type, message=str(error))],
        policy=item.policy_name,
        policy_source=item.policy_source,
    )


def _check_status_consistency(item: EvaluatedEvidence, events: List[Any]) -> None:
    """Reject a "pass" carrying failure events; warn on "fail" with none.

    The verdict derives from ``status`` alone, so a pass with events
    would be an affirming token contradicting its own keylime_failures.
    """
    if item.status == "pass" and events:
        raise KeylimeClaimsError(
            f"evaluation {item.evaluation_id!r} has status 'pass' but carries "
            f"{len(events)} failure event(s); refusing to build an affirming result"
        )
    if item.status == "fail" and not events:
        logger.warning("Evaluation %r has status 'fail' but no failure events", item.evaluation_id)
