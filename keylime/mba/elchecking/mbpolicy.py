import json
from typing import Optional, Set

from keylime import config, keylime_logging
from keylime.failure import Component, Failure
from keylime.mba.elchecking import tests

logger = keylime_logging.init_logging("measured_boot")


def evaluate_bootlog(
    mb_refstate_str: Optional[str],
    mb_measurement_data: tests.Data,
    pcrs_inquote: Set[int],
    agent_id: str,
) -> Failure:
    failure = Failure(Component.MEASURED_BOOT)

    # no evaluation if the refstate is an empty string
    if not mb_refstate_str:
        return failure

    mb_refstate_data = json.loads(mb_refstate_str)

    # no evaluation if the refstate does not load as JSON
    if not mb_refstate_data:
        return failure

    # load policy name
    mb_policy_name = config.get("verifier", "measured_boot_policy_name", fallback="accept-all")

    # pylint: disable=import-outside-toplevel
    from keylime.mba.elchecking import policies as eventlog_policies

    # pylint: enable=import-outside-toplevel
    mb_policy = eventlog_policies.get_policy(mb_policy_name)

    # fallback if we cannot find policy
    # Should not happen in the verifier because we check on startup if the policy exists
    if mb_policy is None:
        logger.warning("Invalid measured boot policy name %s -- using reject-all instead.", mb_policy_name)
        mb_policy_name = "reject-all"
        mb_policy = eventlog_policies.RejectAll()

    # figure out whether the quote contains all quotes to evaluate the policy
    # if there are any PCRs in the policy that are not in the quote, we canot evaluate.
    mb_pcrs_policy = mb_policy.get_relevant_pcrs()
    missing_pcrs = list(mb_pcrs_policy.difference(pcrs_inquote))
    if len(missing_pcrs) > 0:
        logger.error("PCRs specified for policy %s not in quote: %s", mb_policy_name, str(missing_pcrs))
        failure.add_event("missing_pcrs", {"context": "PCRs are missing in quote", "data": missing_pcrs}, True)

    # evaluate the policy
    else:
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
