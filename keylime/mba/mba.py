import importlib
from inspect import isfunction
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from keylime import config
from keylime.failure import Failure

# #########
# Pluggable MBA theory of operations
# #########
# This module (keylime/mba) defines all the "abstract" functions that
# any measured boot attestation implementation has to provide:
# * bootlog_parse
#   * converts a boot log from binary to JSON
#   * authenticates the log by checking the consistency of its digests
#   * provides a set of PCRs that can be verified against the TPM quote
#   * provides a boot aggregate for use by Keylime IMA verification.
# * policy_load
#   * load a policy from a file into a Python string
#   * optionally validate that the policy is syntactically correct (this is TBD)
# * policy_is_valid
#   * test whether a string is valid policy
# * bootlog_evaluate
#   * check the parsed boot log against the loaded policy, and return a list of policy failures
# #########
# Upon initialization MBA loads a number of modules
# as specified in the keylime verifier's configuration file.
# #########
# The implementation for each of the functions described above
# will be chosen from the ordered list of imported modules -- the first imported
# module in the list that implements one of these functions will be called for it.
# #########


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
# list of all imported modules for MBA.
# ###########

_mba_imports = []

# ###########
# import/load measured boot attestation imports
# ###########


def load_imports(skip_custom_policies: Optional[bool] = False) -> None:
    """
    MBA API front-end for importing any modules needed by measured boot attestation.
    :param skip_custom_policies: may be used to prevent the loading of custom policies.
    No outputs.
    Side effects: Reads from keylime configuration files.
      After execution all imports required by MBA are loaded and initialized.
    Exceptions: If any policy engine in the list cannot be loaded.
    """
    try:
        imports: List[Any] = []
        if not skip_custom_policies:
            # import custom policies
            imports = config.getlist("verifier", "measured_boot_imports")
        # these are the defaults
        imports.append("keylime.mba.elchecking.elchecker")
        imports.append("keylime.mba.elchecking.example")
        imports.append("keylime.mba.elparsing.tpm2_tools_elparser")
        # initialize all modules if they carry an initialization function.
        for m in imports:
            _mba_imports.append(importlib.import_module(m, __package__))
    except Exception as e:
        raise ValueError from e


# ##########
# parse a boot log to JSON
# ##########


def bootlog_parse(bootlog_b64: Optional[str], hash_alg: str) -> Tuple[MBPCRDict, MBAgg, MBLog, Failure]:
    """
    MBA API front-end for parsing a binary boot log.

    :param bootlog_b64: a b64 encoded version of the binary boot eventlog from the agent's /sys/kernel directory
    :param hash_alg: the expected hash algorithm to use when decoding the boot log. This is a string, something like
    "sha1" or "sha256".
    :returns:
    * mb_pcrs_hashes: the expected hash values for all PCRs mentioned in the boot log, using the input hash_alg.
    * boot_aggregates: all boot aggregates calculated by the parsed event log.
      This typically includes the aggregate of PCRs 0 to 9, although for sha1 algorithms we only consider PCRs 0 to 7.
    * mb_data: the actual decoded boot log, as a JSON array of events.
    * mb_failure: a list of all failures encountered while parsing the event log.
    """

    try:
        m = _find_implementation("bootlog_parse")
        return m.bootlog_parse(bootlog_b64, hash_alg)  # type: ignore[no-any-return]
    except Exception as e:
        raise ValueError from e


# ##########
# read a policy definition (aka "mb_policy") from a file.
# ##########


def policy_load(policy_path: Optional[str] = None) -> str:
    """
    MBA API front-end for loading an actual policy file.
    :param policy_path: <optional> name of policy file to load
    :returns: a string defining the policy.
    Errors: if the policy file cannot be read, or contains errors, this function may
    cause exceptions.

    TODO: default policy should probably not be defined, because it depends on the policy engine itself?
    """

    try:
        m = _find_implementation("policy_load")
        return m.policy_load(policy_path)  # type: ignore[no-any-return]
    except Exception as e:
        raise ValueError from e


# ##########
# policy validator
# ##########


def policy_is_valid(mb_policy: Optional[str]) -> bool:
    """
    MBA API front-end for checking the validity of a MBA policy (aka mb_policy).
    :param mb_policy: a string describing the policy
    :returns: true if the string is valid policy
    """
    try:
        m = _find_implementation("policy_is_valid")
        return m.policy_is_valid(mb_policy)  # type: ignore[no-any-return]
    except Exception as e:
        raise ValueError from e


# ##########
# evaluate a (parsed) boot log against a policy
# ##########


def bootlog_evaluate(
    policy_data: Optional[str],
    measurement_data: MBLog,
    pcrsInQuote: Set[int],
    agent_id: str,
) -> Failure:
    """
    MBA API front-end for evaluating a measured boot event log against a policy.
    :param policy_data: policy definition (aka "mb_policy") (as a string).
    :param measurement_data: parsed measured boot event log as produced by `bootlog_parse`
    :param pcrsInQuote: a set of PCRs provided by the quote.
    :param agent_id: the UUID of the keylime agent sending this data.
    :returns: list of all failures encountered while evaluating the boot log against the policy.
    """
    try:
        m = _find_implementation("bootlog_evaluate")
        return m.bootlog_evaluate(policy_data, measurement_data, pcrsInQuote, agent_id)  # type: ignore[no-any-return]
    except Exception as e:
        raise ValueError from e


# ###########
# MBA internal function: find an implementation for pluggable functions.
# ###########


def _find_implementation(functionname: str) -> Any:
    """
    This function finds the correct implementation for any of the pluggable functions in MBA
    """
    for m in _mba_imports:
        if hasattr(m, functionname) and isfunction(getattr(m, functionname)):
            return m
    raise ValueError(f"No implementation for function {functionname} found among measured boot imports")


# ###########
# MB policy to store into the database
# ###########


def mb_policy_db_contents(mb_policy_name: str, mb_policy: Optional[str]) -> Dict[str, Any]:
    """Assembles a mb_policy dictionary to be written into the database"""
    mb_policy_db_format: Dict[str, Any] = {}

    mb_policy_db_format["name"] = mb_policy_name
    mb_policy_db_format["mb_policy"] = mb_policy

    return mb_policy_db_format
