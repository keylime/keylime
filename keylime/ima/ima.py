import copy
import enum
import functools
import hashlib
import json
from typing import Any, Dict, List, Optional, Pattern, Tuple, Type

import jsonschema

from keylime import config, keylime_logging, signing
from keylime.agentstates import AgentAttestState
from keylime.common import algorithms, validators
from keylime.common.algorithms import Hash
from keylime.dsse import dsse
from keylime.failure import Component, Failure
from keylime.ima import ast, file_signatures, ima_dm
from keylime.ima.file_signatures import IMA_KEYRING_JSON_SCHEMA, ImaKeyrings
from keylime.ima.types import RuntimePolicyType

logger = keylime_logging.init_logging("ima")


# The version of the IMA policy format that is supported by this keylime release
RUNTIME_POLICY_CURRENT_VERSION = 1


class RUNTIME_POLICY_GENERATOR(enum.IntEnum):
    Unknown = 0
    EmptyAllowList = 1
    CompatibleAllowList = 2
    LegacyAllowList = 3


# A correctly formatted empty IMA policy.
#
# Older versions of Keylime allowlists did not have the "log_hash_alg"
# parameter. Hard-coding it to "sha1" is perfectly fine, and the fact one
# specifies a different algorithm on the kernel command line (e.g., ima_hash=sha256)
# does not affect normal operation of Keylime, since it does not validate the
# hash algorithm received from agent's IMA runtime measurements.
# The only situation where this hard-coding would become a problem is if and when
# the kernel maintainers decide to use a different algorithm for template-hash.
EMPTY_RUNTIME_POLICY: RuntimePolicyType = {
    "meta": {
        "version": RUNTIME_POLICY_CURRENT_VERSION,
        "generator": RUNTIME_POLICY_GENERATOR.EmptyAllowList,
    },
    "release": 0,
    "digests": {},
    "excludes": [],
    "keyrings": {},
    "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1", "dm_policy": None},
    "ima-buf": {},
    "verification-keys": "",
}


RUNTIME_POLICY_SCHEMA = {
    "type": "object",
    "required": ["meta", "release", "digests", "excludes", "keyrings", "ima", "ima-buf", "verification-keys"],
    "properties": {
        "meta": {
            "type": "object",
            "required": ["version", "generator"],
            "properties": {
                "version": {"type": "integer", "minimum": 0},
                "generator": {
                    "type": "integer",
                    "minimum": min(list(RUNTIME_POLICY_GENERATOR)),
                    "maximum": max(list(RUNTIME_POLICY_GENERATOR)),
                },
                "timestamp": {"type": "string"},
            },
        },
        "release": {"type": "integer", "minimum": 0},
        "digests": {"$ref": "#/definitions/digests-object"},
        "excludes": {"type": "array", "items": {"type": "string"}},
        "keyrings": {"$ref": "#/definitions/digests-object"},
        "ima": {
            "type": "object",
            "required": ["ignored_keyrings", "log_hash_alg", "dm_policy"],
            "properties": {
                "ignored_keyrings": {"type": "array", "items": {"type": "string"}},
                "log_hash_alg": {"type": "string", "enum": ["sha1", "sha256", "sha384", "sha512"]},
                "dm_policy": {"type": "null"},
            },
        },
        "ima-buf": {"$ref": "#/definitions/digests-object"},
        "verification-keys": {"type": "string"},
    },
    "definitions": {
        "digests-object": {
            "type": "object",
            "patternProperties": {
                "^": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^[0-9a-f]{40,128}$"},
                    "minItems": 1,
                    "uniqueItems": False,
                }
            },
        }
    },
}


def _validate_ima_ng(
    exclude_regex: Optional[Pattern[str]],
    runtime_policy: Optional[RuntimePolicyType],
    digest: ast.Digest,
    path: ast.Name,
    hash_types: str = "digests",
) -> Failure:
    failure = Failure(Component.IMA, ["validation", "ima-ng"])
    if runtime_policy is not None:
        if exclude_regex is not None and exclude_regex.match(path.name):
            logger.debug("IMA: ignoring excluded path %s", path)
            return failure

        accept_list = runtime_policy[hash_types].get(path.name, None)  # type: ignore
        if accept_list is None:
            logger.warning("File not found in allowlist: %s", path.name)
            failure.add_event("not_in_allowlist", f"File not found in allowlist: {path.name}", True)
            return failure

        hex_hash = digest.hash.hex()
        if hex_hash not in accept_list:
            logger.warning(
                "Hashes for file %s don't match %s not in %s",
                path.name,
                hex_hash,
                str(accept_list),
            )
            failure.add_event(
                "runtime_policy_hash",
                {
                    "message": "Hash not found in runtime policy",
                    "got": hex_hash,
                    "expected": accept_list,
                },
                True,
            )
            return failure

    return failure


def _validate_ima_sig(
    exclude_regex: Optional[Pattern[str]],
    ima_keyrings: Optional[file_signatures.ImaKeyrings],
    runtime_policy: Optional[RuntimePolicyType],
    digest: ast.Digest,
    path: ast.Name,
    signature: ast.Signature,
) -> Failure:
    failure = Failure(Component.IMA, ["validator", "ima-sig"])
    if ima_keyrings and signature:
        if exclude_regex is not None and exclude_regex.match(path.name):
            logger.debug("IMA: ignoring excluded path %s", path.name)
            return failure

        if ima_keyrings.integrity_digsig_verify(signature.data, digest.hash, digest.algorithm):
            logger.debug("signature for file %s is good", path)
            return failure

    # If signature validation failed check if the runtime_policy matches
    if runtime_policy is not None:
        logger.debug("signature for file %s could not be validated. Trying runtime_policy.", path.name)
        return _validate_ima_ng(exclude_regex, runtime_policy, digest, path)

    # If we don't have a runtime_policy and don't have a keyring we just ignore the validation.
    if ima_keyrings is None:
        return failure

    logger.warning("signature verification for file %s failed and no runtime_policy is available", path.name)
    failure.add_event("invalid_signature", f"signature for file {path.name} could not be validated", True)
    return failure


def _validate_ima_buf(
    exclude_regex: Optional[Pattern[str]],
    runtime_policy: Optional[RuntimePolicyType],
    ima_keyrings: Optional[file_signatures.ImaKeyrings],
    dm_validator: Optional[ima_dm.DmIMAValidator],
    digest: ast.Digest,
    path: ast.Name,
    data: ast.Buffer,
) -> Failure:
    failure = Failure(Component.IMA)
    # Is data.data a key?
    try:
        pubkey, keyidv2 = file_signatures.get_pubkey(data.data)
    except ValueError as ve:
        failure.add_event("invalid_key", f"key from {path.name} does not have a supported key: {ve}", True)
        return failure

    if pubkey:
        ignored_keyrings = []
        if runtime_policy:
            ignored_keyrings = runtime_policy.get("ima", {}).get("ignored_keyrings", [])

        if "*" not in ignored_keyrings and path.name not in ignored_keyrings:
            failure = _validate_ima_ng(exclude_regex, runtime_policy, digest, path, hash_types="keyrings")
            if not failure:
                # Add the key only now that it's validated (no failure)
                if ima_keyrings is not None:
                    ima_keyrings.add_pubkey_to_keyring(pubkey, path.name, keyidv2=keyidv2)
    # Check if this is a device mapper entry only if we have a validator for that
    elif dm_validator is not None and path.name in dm_validator.valid_names:
        failure = dm_validator.validate(digest, path, data)
    else:
        # handling of generic ima-buf entries that for example carry a hash in the buf field
        failure = _validate_ima_ng(exclude_regex, runtime_policy, digest, path, hash_types="ima-buf")

    # Anything else evaluates to true for now
    return failure


def _process_measurement_list(
    agentAttestState: AgentAttestState,
    lines: List[str],
    hash_alg: Hash,
    runtime_policy: Optional[RuntimePolicyType] = None,
    pcrval: Optional[str] = None,
    ima_keyrings: Optional[ImaKeyrings] = None,
    boot_aggregates: Optional[Dict[str, List[str]]] = None,
) -> Tuple[str, Failure]:
    failure = Failure(Component.IMA)
    running_hash = agentAttestState.get_pcr_state(config.IMA_PCR, hash_alg)
    assert running_hash

    found_pcr = pcrval is None
    errors: Dict[Type[ast.Mode], int] = {}
    pcrval_bytes = b""
    if pcrval is not None:
        pcrval_bytes = bytes.fromhex(pcrval)

    if runtime_policy is not None:
        exclude_list = runtime_policy.get("excludes")
    else:
        exclude_list = None

    ima_log_hash_alg = algorithms.Hash.SHA1
    if runtime_policy is not None:
        try:
            ima_log_hash_alg = algorithms.Hash(runtime_policy["ima"]["log_hash_alg"])
        except ValueError:
            logger.warning(
                "Specified IMA log hash algorithm %s is not a valid algorithm! Defaulting to SHA1.",
                runtime_policy["ima"]["log_hash_alg"],
            )

    if boot_aggregates and runtime_policy:
        if "boot_aggregate" not in runtime_policy["digests"]:
            runtime_policy["digests"]["boot_aggregate"] = []
        for alg in boot_aggregates.keys():
            for val in boot_aggregates[alg]:
                if val not in runtime_policy["digests"]["boot_aggregate"]:
                    runtime_policy["digests"]["boot_aggregate"].append(val)

    exclude_list_compiled_regex, err_msg = validators.valid_exclude_list(exclude_list)
    if err_msg:
        # This should not happen as the exclude list has already been validated
        # by the verifier before acceping it. This is a safety net just in case.
        err_msg += " Exclude list will be ignored."
        logger.error(err_msg)

    # Setup device mapper validation
    dm_validator = None
    if runtime_policy is not None:
        dm_policy = runtime_policy["ima"]["dm_policy"]

        if dm_policy is not None:
            dm_validator = ima_dm.DmIMAValidator(dm_policy)
            dm_state = agentAttestState.get_ima_dm_state()
            # Only load state when using incremental attestation
            if agentAttestState.get_next_ima_ml_entry() != 0:
                dm_validator.state_load(dm_state)

    ima_validator = ast.Validator(
        {
            ast.ImaSig: functools.partial(_validate_ima_sig, exclude_list_compiled_regex, ima_keyrings, runtime_policy),
            ast.ImaNg: functools.partial(_validate_ima_ng, exclude_list_compiled_regex, runtime_policy),
            ast.Ima: functools.partial(_validate_ima_ng, exclude_list_compiled_regex, runtime_policy),
            ast.ImaBuf: functools.partial(
                _validate_ima_buf, exclude_list_compiled_regex, runtime_policy, ima_keyrings, dm_validator
            ),
        }
    )

    pcr_match_line = -1
    log_length = 0

    # Iterative attestation may send us no log [len(lines) == 1]; compare last know PCR 10 state
    # against current PCR state.
    # Since IMA's append to the log and PCR extend as well as Keylime's retrieval of the quote, reading
    # of PCR 10 and retrieval of the log are not atomic, we may get a quote that does not yet take into
    # account the next-appended measurements' [len(lines) >= 2] PCR extension(s). In fact, the value of
    # the PCR may lag the log by several entries.
    if not found_pcr:
        found_pcr = running_hash == pcrval_bytes
        pcr_match_line = 0

    for linenum, line in enumerate(lines):
        # remove only the newline character, as there can be the space
        # as the delimiter character followed by an empty field at the
        # end
        line = line.strip("\n")
        if line == "":
            continue

        log_length += 1

        try:
            entry = ast.Entry(line, ima_validator, ima_hash_alg=ima_log_hash_alg, pcr_hash_alg=hash_alg)

            # update hash
            running_hash = hash_alg.hash(running_hash + entry.pcr_template_hash)

            validation_failure = entry.invalid()

            if validation_failure:
                failure.merge(validation_failure)
                errors[type(entry.mode)] = errors.get(type(entry.mode), 0) + 1

            if not found_pcr:
                # End of list should equal pcr value
                found_pcr = running_hash == pcrval_bytes
                if found_pcr:
                    pcr_match_line = linenum + 1
                    logger.debug("Found match at linenum %s", linenum + 1)
                    # We always want to have the very last line for the attestation, so
                    # we keep the previous runninghash, which is not the last one!
                    agentAttestState.update_ima_attestation(int(entry.pcr), running_hash, linenum + 1)
                    if dm_validator:
                        agentAttestState.set_ima_dm_state(dm_validator.state_dump())

        except ast.ParserError:
            failure.add_event("entry", f"Line was not parsable into a valid IMA entry: {line}", True, ["parser"])
            logger.error("Line was not parsable into a valid IMA entry: %s", line)

    # check PCR value has been found
    if not found_pcr:
        logger.error("IMA measurement list does not match TPM PCR %s", pcrval)
        failure.add_event("pcr_mismatch", f"IMA measurement list does not match TPM PCR {pcrval}", True)
    elif not agentAttestState.check_quote_progress(pcr_match_line, log_length):
        logger.error("PCR quote did not make progress to catch up with the log")
        failure.add_event("quote_progress", "PCR quote did not make progress to catch up with log", True)

    # Check if any validators failed
    if sum(errors.values()) > 0:
        error_msg = "IMA ERRORS: Some entries couldn't be validated. Number of failures in modes: "
        error_msg += ", ".join([f"{k.__name__ } {v}" for k, v in errors.items()])
        logger.error("%s.", error_msg)

    return running_hash.hex(), failure


def process_measurement_list(
    agentAttestState: AgentAttestState,
    lines: List[str],
    runtime_policy: Optional[RuntimePolicyType] = None,
    pcrval: Optional[str] = None,
    ima_keyrings: Optional[ImaKeyrings] = None,
    boot_aggregates: Optional[Dict[str, List[str]]] = None,
    hash_alg: algorithms.Hash = algorithms.Hash.SHA1,
) -> Tuple[str, Failure]:
    failure = Failure(Component.IMA)
    try:
        running_hash, failure = _process_measurement_list(
            agentAttestState,
            lines,
            hash_alg,
            runtime_policy=runtime_policy,
            pcrval=pcrval,
            ima_keyrings=ima_keyrings,
            boot_aggregates=boot_aggregates,
        )
    except:  # pylint: disable=try-except-raise
        raise
    finally:
        if failure:
            # TODO currently reset on any failure which might be an issue
            agentAttestState.reset_ima_attestation()

    return running_hash, failure


# Read IMA policy files from disk, validate signatures and checksums, and prepare for sending.
def read_runtime_policy(
    runtime_policy_path: Optional[str] = None,
    checksum: Optional[str] = "",
    runtime_policy_key_file: Optional[str] = None,
) -> Tuple[bytes, bytes]:
    al_key = b""
    verify_signature = False

    # If user only wants signatures then a runtime policy is not required
    if runtime_policy_path is None or runtime_policy_path == "":
        alist_bytes = json.dumps(copy.deepcopy(EMPTY_RUNTIME_POLICY)).encode()

    elif isinstance(runtime_policy_path, str):
        with open(runtime_policy_path, "rb") as alist_f:
            logger.debug("Loading runtime policy from %s", runtime_policy_path)
            alist_bytes = alist_f.read()

    else:
        raise Exception("Invalid runtime policy provided")

    # Load signatures/keys if needed
    if runtime_policy_key_file:
        logger.debug(
            "Loading key (%s) and checking against runtime policy (%s)", runtime_policy_key_file, runtime_policy_path
        )
        verify_signature = True
        with open(runtime_policy_key_file, "rb") as key_f:
            al_key = key_f.read()

    if json.loads(alist_bytes).get("payload"):
        logger.debug(
            "Loading key (%s) and checking against runtime policy (%s)", runtime_policy_key_file, runtime_policy_path
        )
        verify_signature = True

    # Verify runtime policy. This function checks for correct JSON formatting, and
    # will also verify signatures if provided.
    try:
        verify_runtime_policy(alist_bytes, al_key, verify_sig=verify_signature)
    except ImaValidationError as error:
        message = f"Validation for runtime policy {runtime_policy_path} failed! Error: {error.message}"
        raise Exception(message) from error

    sha256 = hashlib.sha256()
    sha256.update(alist_bytes)
    calculated_checksum = sha256.hexdigest()
    logger.debug("Loaded runtime policy from %s with checksum %s", runtime_policy_path, calculated_checksum)

    if checksum:
        if checksum == calculated_checksum:
            logger.debug("Runtime policy passed checksum validation")
        else:
            raise Exception(
                f"Checksum of runtime policy does not match! Expected {checksum}, Calculated {calculated_checksum}"
            )

    return alist_bytes, al_key


def runtime_policy_db_contents(runtime_policy_name: str, runtime_policy: str, tpm_policy: str = "") -> Dict[str, Any]:
    """Assembles a runtime policy dictionary to be written on the database"""
    runtime_policy_db_format: Dict[str, Any] = {}
    runtime_policy_db_format["name"] = runtime_policy_name
    # TODO: This was required to ensure e2e CI tests pass
    if runtime_policy == "{}":
        runtime_policy_db_format["ima_policy"] = None
    else:
        runtime_policy_db_format["ima_policy"] = runtime_policy
    runtime_policy_bytes = runtime_policy.encode()
    runtime_policy_dict = deserialize_runtime_policy(runtime_policy)

    validate_runtime_policy(runtime_policy_dict)

    if "meta" in runtime_policy_dict:
        if "generator" in runtime_policy_dict["meta"]:
            runtime_policy_db_format["generator"] = runtime_policy_dict["meta"]["generator"]
        else:
            runtime_policy_db_format["generator"] = RUNTIME_POLICY_GENERATOR.Unknown
    if tpm_policy:
        runtime_policy_db_format["tpm_policy"] = tpm_policy

    runtime_policy_db_format["checksum"] = hashlib.sha256(runtime_policy_bytes).hexdigest()

    return runtime_policy_db_format


class ImaValidationError(Exception):
    def __init__(self, message: str, code: int):
        self.message = message
        self.code = code
        super().__init__(self.message)


def verify_runtime_policy(
    runtime_policy: bytes,
    runtime_policy_key: Optional[bytes] = None,
    verify_sig: Optional[bool] = True,
) -> None:
    """
    Verify that a runtime policy is valid. If provided runtime policy has a detached signature, verify the signature.
    """

    if runtime_policy is None:
        raise ImaValidationError(
            message="No IMA policy provided!",
            code=400,
        )

    # validate that the runtime_policy is proper JSON
    try:
        runtime_policy_json = json.loads(runtime_policy)
    except Exception as error:
        raise ImaValidationError(message="Runtime policy is not valid JSON!", code=400) from error

    if verify_sig and not runtime_policy_key:
        raise ImaValidationError(
            message="Runtime policy signature verification required but no key was given!", code=401
        )

    # detect if runtime policy is DSSE
    if runtime_policy_json.get("payload"):
        if verify_sig:
            if not signing.verify_dsse_envelope(runtime_policy, runtime_policy_key):
                raise ImaValidationError(message="Runtime policy failed DSSE signature verification!", code=401)
            logger.info("Runtime policy passed DSSE signature verification")
        else:
            runtime_policy = dsse.b64dec(runtime_policy_json["payload"])
    else:
        if verify_sig:
            raise ImaValidationError(message="Runtime policy is not signed!", code=400)

    # Validate exclude list contains valid regular expressions
    _, excl_err_msg = validators.valid_exclude_list(runtime_policy_json.get("exclude"))
    if excl_err_msg:
        raise ImaValidationError(
            message=f"{excl_err_msg} Exclude list regex is misformatted. Please correct the issue and try again.",
            code=400,
        )


def deserialize_runtime_policy(runtime_policy: str) -> RuntimePolicyType:
    """
    Converts policies stored in the database to JSON (if applicable), for use in code.
    """

    runtime_policy_loaded: Dict[str, Any] = json.loads(runtime_policy)

    # If runtime policy is formatted as a DSSE envelope, extract policy from payload.
    if runtime_policy_loaded.get("payload"):
        runtime_policy_deserialized: RuntimePolicyType = json.loads(dsse.b64dec(runtime_policy_loaded["payload"]))
    else:
        runtime_policy_deserialized = json.loads(runtime_policy)

    return runtime_policy_deserialized


def validate_runtime_policy(runtime_policy: RuntimePolicyType) -> None:
    """
    Validate a runtime policy against the schema.
    """
    try:
        jsonschema.validate(instance=runtime_policy, schema=RUNTIME_POLICY_SCHEMA)
        verification_keys = runtime_policy.get("verification-keys", "")
        if verification_keys:
            # Verification keys is a string in JSON format. Parse it to verify
            # against the schema
            j = json.loads(verification_keys)
            jsonschema.validate(instance=j, schema=IMA_KEYRING_JSON_SCHEMA)
    except Exception as error:
        msg = str(error).split("\n", 1)[0]
        raise ImaValidationError(message=f"{msg}", code=400) from error


def empty_policy() -> RuntimePolicyType:
    """Return an empty runtime policy."""
    return copy.deepcopy(EMPTY_RUNTIME_POLICY)
