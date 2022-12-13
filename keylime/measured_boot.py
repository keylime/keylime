import argparse
import json
import sys
import traceback
from typing import Any, Dict, Optional, Set, Tuple

from keylime import config, keylime_logging
from keylime.elchecking import tests
from keylime.elchecking.policies import Policy, RefState
from keylime.failure import Component, Failure

logger = keylime_logging.init_logging("measured_boot")


def read_mb_refstate(mb_path: Optional[str] = None) -> Optional[str]:
    if mb_path is None:
        mb_path = config.get("tenant", "mb_refstate")

    mb_data: Optional[str] = None
    # Purposefully die if path doesn't exist
    with open(mb_path, encoding="utf-8") as f:
        mb_data = json.load(f)

    logger.debug("Loaded measured boot reference state from %s", mb_path)

    return mb_data


def get_policy(mb_refstate_str: Optional[str]) -> Tuple[Optional[Policy], str, Optional[Dict[str, Any]]]:
    """Convert the mb_refstate_str to JSON and get the measured boot policy.
    :param mb_refstate_str: String representation of measured boot reference state
    :returns: Returns
                  * the measured boot policy object
                  * the JSON object of the measured boot reference state
              both can be None if mb_refstate_str was empty
    """

    mb_policy_name = "empty"

    if mb_refstate_str:
        mb_refstate_data = json.loads(mb_refstate_str)
    else:
        mb_refstate_data = None

    if mb_refstate_data:
        mb_policy_name = config.get("verifier", "measured_boot_policy_name", fallback="accept-all")
        # pylint: disable=import-outside-toplevel
        from keylime.elchecking import policies as eventlog_policies

        # pylint: enable=import-outside-toplevel
        mb_policy = eventlog_policies.get_policy(mb_policy_name)
        # Should not happen in the verifier because we check on startup if the policy exists
        if mb_policy is None:
            logger.warning("Invalid measured boot policy name %s -- using reject-all instead.", mb_policy_name)
            mb_policy_name = "reject-all"
            mb_policy = eventlog_policies.RejectAll()

        mb_pcrs_config = frozenset(config.MEASUREDBOOT_PCRS)
        mb_pcrs_policy = mb_policy.get_relevant_pcrs()
        if not mb_pcrs_policy <= mb_pcrs_config:
            logger.error(
                "Measured boot policy considers PCRs %s, which are not among the configured set %s",
                set(mb_pcrs_policy - mb_pcrs_config),
                set(mb_pcrs_config),
            )
    else:
        mb_policy = None

    return mb_policy, mb_policy_name, mb_refstate_data


def evaluate_policy(
    mb_policy: Optional[Policy],
    mb_policy_name: str,
    mb_refstate_data: RefState,
    mb_measurement_data: tests.Data,
    pcrsInQuote: Set[int],
    pcrPrefix: str,
    agent_id: str,
) -> Failure:
    failure = Failure(Component.MEASURED_BOOT)
    missing = list(set(config.MEASUREDBOOT_PCRS).difference(pcrsInQuote))
    if len(missing) > 0:
        logger.error("%sPCRs specified for measured boot not in quote: %s", pcrPrefix, missing)
        failure.add_event("missing_pcrs", {"context": "PCRs are missing in quote", "data": missing}, True)
    try:
        if mb_policy is None:
            raise Exception("missing measured boot policy")
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", default="mbtest.txt")
    args = parser.parse_args()
    try:
        read_mb_refstate(args.infile)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
