import json
from typing import Dict, List, Mapping, Optional, Set, Tuple

from keylime import config
from keylime.common import algorithms
from keylime.failure import Failure
from keylime.mba.elchecking import mbpolicy, policies
from keylime.mba.elparsing import tpm2_tools_elparser

# ##########
# type definition for a measured boot log represented in Python.
# MBLog is the internal python representation of the log: a list of events.
# MBPCRDict is a dictionary with PCR numbers as keys and hash values represented as large integers
# MBAgg is the list of generated boot aggregates
# ##########
# Note -- mypy does not support recursive type definitions, so we use 'object'
# in the definition of MBLog instead of defining entries.

MBLog = Mapping[str, object]
MBPCRDict = Dict[str, int]
MBAgg = Optional[Dict[str, List[str]]]

# ###########
# import/load policy engine
# ###########


def load_policy_engine() -> None:
    """
    MBA API front-end for importing the policy engine.
    No inputs, but implementation *will* read from keylime configuration files.
    No outputs.
    Side effects: policy engine is now loaded.
    Exceptions: If the policy engine cannot be loaded.
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
    policy_data: Optional[str],
    measurement_data: MBLog,
    pcrsInQuote: Set[int],
    agent_id: str,
) -> Failure:
    """
    MBA API front-end for evaluating a measured boot event log against a policy.
    :param policy_data: policy definition (aka "refstate") (as a string).
    :param measurement_data: parsed measured boot event log as produced by `parse_bootlog`
    :param pcrsInQuote: a set of PCRs provided by the quote.
    :param agent_id: the UUID of the keylime agent sending this data.
    :returns: list of all failures encountered while evaluating the boot log against the policy.
    """
    return mbpolicy.evaluate_bootlog(policy_data, measurement_data, pcrsInQuote, agent_id)


# ##########
# parser initialization
# ##########


def load_parser_engine() -> None:
    """
    MBA API front end for initializing a binary event log parser.
    No inputs, but implementation *will* read from keylime configuration files.
    No returns.
    Side effects: parser engine is loaded.
    Exceptions raised: gives the opportunity to the system to raise errors
    if the event log parser cannot be loaded/initialized.
    """
    try:
        tpm2_tools_version = tpm2_tools_elparser.tpm2_tools_getversion()
        if tpm2_tools_version == "unknown":
            raise ValueError("TPM2-TOOLS: version cannot be determined or unsupported")
    except Exception as e:
        raise ValueError from e


# ##########
# parsing a boot log
# ##########


def parse_bootlog(bootlog_b64: Optional[str], hash_alg: algorithms.Hash) -> Tuple[MBPCRDict, MBAgg, MBLog, Failure]:
    """
    MBA API front-end for parsing a binary boot log.

    :param bootlog_b64: a b64 encoded version of the binary boot eventlog from the agent's /sys/kernel directory
    :param hash_alg: the expected hash algorithm to use when decoding the boot log. This may result in an error
    if the hash algorithm was not actually used in the boot log.

    :returns:
    * mb_pcrs_hashes: the expected hash values for all PCRs mentioned in the boot log, using the input hash_alg.
    * boot_aggregates: all boot aggregates calculated by the parsed event log.
      This typically includes the aggregate of PCRs 0 to 9, although for sha1 algorithms we only consider PCRs 0 to 7.
    * mb_data: the actual decoded boot log, as a JSON array of events.
    * mb_failure: a list of all failures encountered while parsing the event log.
    """
    return tpm2_tools_elparser.parse_bootlog(bootlog_b64, hash_alg)
