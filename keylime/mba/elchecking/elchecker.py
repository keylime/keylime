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
    Returns true if the policy argument is a valid nonempty policy
    """
    if not mb_refstate:
        return False
    try:
        mb_refstate_obj = json.loads(mb_refstate)
    except Exception as _:
        return False
    if not mb_refstate_obj:
        return False
    if len(mb_refstate_obj) == 0:
        return False
    return True


def bootlog_evaluate(
    mb_refstate_str: Optional[str],
    mb_measurement_data: tests.Data,
    pcrs_inquote: Set[int],
    agent_id: str,
) -> Failure:
    """
    Evaluating a measured boot event log against a policy
    :param policy_data: policy definition (aka "refstate") (as a string).
    :param measurement_data: parsed measured boot event log as produced by `parse_bootlog`
    :param pcrsInQuote: a set of PCRs provided by the quote.
    :param agent_id: the UUID of the keylime agent sending this data.
    :returns: list of all failures encountered while evaluating the boot log against the policy.
    """
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

    # pylint: enable=import-outside-toplevel
    mb_policy = policies.get_policy(mb_policy_name)

    # fallback if we cannot find policy
    # Should not happen in the verifier because we check on startup if the policy exists
    if mb_policy is None:
        logger.warning("Invalid measured boot policy name %s -- using reject-all instead.", mb_policy_name)
        mb_policy_name = "reject-all"
        mb_policy = policies.RejectAll()

    # figure out whether the quote contains all quotes to evaluate the policy
    # if there are any PCRs in the policy that are not in the quote, we canot evaluate.
    mb_pcrs_policy = mb_policy.get_relevant_pcrs()
    missing_pcrs = list(mb_pcrs_policy.difference(pcrs_inquote))
    reason = None
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


logger.debug("mba.elchecking.elchecker: policy names = %s", str(policies.get_policy_names()))
