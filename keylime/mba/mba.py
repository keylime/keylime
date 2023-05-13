import json
from typing import Dict, Optional, Set

from keylime import config
from keylime.failure import Failure
from keylime.mba.elchecking import mbpolicy, policies

# ###########
# import/load policy engine
# ###########


def load_policy_engine() -> None:
    """
    MBA API front-end for importing the policy engine.
    Inputs: <none>, but may read from keylime configuration files.
    Outputs: <none>, but the keylime policy engine is now loaded.
    Errors: Possible exceptions raised if the policy engine cannot be loaded.
    """
    try:
        policies.load_policies()
    except Exception as e:
        raise ValueError from e


# ##########
# read a policy definition (aka "refstate") from a file.
# ##########


def load_policy_file(policy_path: Optional[str] = None) -> str:
    """
    MBA API front-end for loading an actual policy file.
    Inputs: <optional> name of policy file to load
    Outputs: a string defining the policy.
    Errors: if the policy file cannot be read, or contains errors, this function may
    cause exceptions.

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


# ##########
# evaluate a (parsed) boot log against a policy
# ##########


def evaluate_bootlog(
    mb_policy_data: Optional[str],
    mb_measurement_data: Dict[str, str],
    pcrsInQuote: Set[int],
    agent_id: str,
) -> Failure:
    """
    MBA API front-end for evaluating a measured boot event log against a policy.
    Inputs:
    * mb_policy_data: policy definition (aka "refstate") (as a string).
    * mb_measurement_data: parsed measured boot event log.
    * pcrsInQuote: a set of PCRs provided by the quote.
    * agent_id: the UUID of the keylime agent sending this data.
    Output:
    * The list of all failures encountered while evaluating the boot log against the policy.
    """
    return mbpolicy.evaluate_policy(mb_policy_data, mb_measurement_data, pcrsInQuote, agent_id)
