import json
from typing import Optional, Set

from keylime import config, keylime_logging
from keylime.failure import Component, Failure
from keylime.mba.elchecking import policies, tests

logger = keylime_logging.init_logging("measured_boot")


def policy_load(policy_path: Optional[str] = None) -> str:
    """
    Load (and validates) an actual policy file.
    :param policy_path: <optional> name of policy file to load
    :returns: a string defining the policy.
    Errors: if the policy file cannot be read, or contains errors, this function may
    cause exceptions. Validation in this case is to confirm that the file
    is formatted as proper JSON; nothing more.

    TODO: default policy should probably not be defined, because it depends on the policy engine itself?
    """
    try:
        if policy_path is None:
            policy_path = config.get("tenant", "mb_refstate")
        with open(policy_path, encoding="utf-8") as f:
            mb_policy_data = json.load(f)
            return json.dumps(mb_policy_data)
    except Exception as e:
        raise ValueError from e


def policy_is_valid(mb_refstate: Optional[str]) -> bool:
    """
    Returns true if the policy argument is a valid policy.
    An empty dict {} is considered valid (accept-all policy).
    """
    if not mb_refstate:
        return False
    try:
        mb_refstate_obj = json.loads(mb_refstate)
    except Exception as _:
        return False
    # mb_refstate_obj can be an empty dict {} which is valid (accept-all)
    if mb_refstate_obj is None:
        return False
    return True


def bootlog_evaluate(
    mb_refstate_str: Optional[str],
    mb_measurement_data: tests.Data,
    pcrs_inquote: Set[int],
    agent_id: str,
    quote_hash_alg: Optional[str] = None,
    log_bound_pcrs: Optional[Set[int]] = None,
) -> Failure:
    """
    Evaluating a measured boot event log against a policy
    :param policy_data: policy definition (aka "refstate") (as a string).
    :param measurement_data: parsed measured boot event log as produced by `parse_bootlog`
    :param pcrs_inquote: the PCRs the quote validated.
    :param agent_id: the UUID of the keylime agent sending this data.
    :param quote_hash_alg: the PCR bank authenticated by the quote.
    :param log_bound_pcrs: PCRs whose event-log value matched the quote. A PCR the
        policy relies on must be in this set. A policy that requires this set
        (ordered-replay) rejects when it is omitted; other policies fall back to
        pcrs_inquote.
    :returns: list of all failures encountered while evaluating the boot log against the policy.
    """
    failure = Failure(Component.MEASURED_BOOT)

    # Load policy name and policy first, so a malformed reference state is reported
    # as an invalid operator policy rather than raising.
    mb_policy_name = config.get("verifier", "measured_boot_policy_name", fallback="accept-all")
    mb_policy = policies.get_policy(mb_policy_name)

    # fallback if we cannot find policy
    # Should not happen in the verifier because we check on startup if the policy exists
    if mb_policy is None:
        logger.warning("Invalid measured boot policy name %s -- using reject-all instead.", mb_policy_name)
        mb_policy_name = "reject-all"
        mb_policy = policies.RejectAll()

    # Parse the reference state; it may be missing or empty. Malformed JSON is an
    # operator error, not an agent fault, so report it as invalid_mb_policy.
    try:
        mb_refstate_data = json.loads(mb_refstate_str) if mb_refstate_str else None
    except (TypeError, ValueError) as exn:
        logger.error("Measured boot reference state for policy %s is not valid JSON: %s", mb_policy_name, str(exn))
        failure.add_event(
            "invalid_mb_policy",
            {"context": "Invalid measured boot reference state", "policy": mb_policy_name, "reason": str(exn)},
            True,
        )
        return failure

    # An empty or missing reference state means different things per policy. A
    # policy that does not accept it (reject-all, ordered-replay) still runs so the
    # missing content fails closed. A policy that accepts it but must run on every
    # quote or needs the log-bound PCR set also runs, so its hooks take effect.
    # Any other accepting policy (accept-all) passes without further checks.
    if not mb_refstate_data:
        if not mb_policy.accepts_empty_refstate():
            mb_refstate_data = {}
        elif mb_policy.requires_evaluation_every_quote() or mb_policy.requires_log_bound_pcrs():
            mb_refstate_data = {}
        else:
            return failure

    reason = None

    # The quote must bind every PCR the policy relies on. A genuinely missing PCR
    # is reported as missing_pcrs (kept stable for monitoring rules); a reference
    # state the policy cannot read is reported as invalid_mb_policy.
    try:
        relevant_pcrs = mb_policy.get_relevant_pcrs_from_refstate(mb_refstate_data)
    except Exception as exn:
        logger.error("Measured boot policy %s cannot read its reference state: %s", mb_policy_name, str(exn))
        failure.add_event(
            "invalid_mb_policy",
            {"context": "Invalid measured boot reference state", "policy": mb_policy_name, "reason": str(exn)},
            True,
        )
        return failure

    # A PCR the policy relies on is bound only if its event-log value matched the
    # quote. A policy that needs that set (ordered-replay) rejects when a caller
    # omits it; other policies keep the broad quote-PCR set for compatibility.
    if log_bound_pcrs is not None:
        bound_pcrs = log_bound_pcrs
    elif mb_policy.requires_log_bound_pcrs():
        logger.error("Measured boot policy %s requires the quote-bound PCR set, which was not provided", mb_policy_name)
        failure.add_event(
            "quote_context",
            {
                "context": "Quote context does not satisfy measured boot policy",
                "policy": mb_policy_name,
                "reason": "the set of quote-bound PCRs was not provided",
            },
            True,
        )
        return failure
    else:
        bound_pcrs = pcrs_inquote
    missing_pcrs = sorted(relevant_pcrs.difference(bound_pcrs))
    if missing_pcrs:
        logger.error("PCRs specified for policy %s not bound to the log by the quote: %s", mb_policy_name, missing_pcrs)
        failure.add_event("missing_pcrs", {"context": "PCRs are missing in quote", "data": missing_pcrs}, True)
        return failure

    # The quoted PCR bank must satisfy the policy (bank binding).
    try:
        bank_reason = mb_policy.validate_quote_bank(mb_refstate_data, quote_hash_alg)
    except Exception as exn:
        bank_reason = f"quote bank validation failed: {str(exn)}"

    if bank_reason:
        logger.error("Quote context does not satisfy measured boot policy %s: %s", mb_policy_name, bank_reason)
        failure.add_event(
            "quote_context",
            {
                "context": "Quote context does not satisfy measured boot policy",
                "policy": mb_policy_name,
                "reason": bank_reason,
            },
            True,
        )
        return failure

    try:
        reason = mb_policy.evaluate(mb_refstate_data, mb_measurement_data)
    except Exception as exn:
        reason = f"policy evaluation failed: {str(exn)}"

    if reason:
        logger.error(
            "Boot attestation failed for agent %s, policy %s, refstate=%s, reason=%s",
            agent_id,
            mb_policy_name,
            json.dumps(mb_refstate_data),
            reason,
        )
        failure.add_event(
            f"policy_{mb_policy_name}",
            {
                "context": "Boot attestation failed",
                "policy": mb_policy_name,
                "refstate": str(mb_refstate_data),
                "reason": reason,
            },
            True,
        )
    return failure


logger.debug("mba.elchecking.elchecker: policy names = %s", str(policies.get_policy_names()))
