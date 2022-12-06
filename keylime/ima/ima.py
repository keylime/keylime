import base64
import codecs
import copy
import datetime
import functools
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Pattern, Set, TextIO, Tuple, Type, Union, cast

from keylime import config, keylime_logging, signing
from keylime.agentstates import AgentAttestState
from keylime.common import algorithms, validators
from keylime.common.algorithms import Hash
from keylime.failure import Component, Failure
from keylime.ima import ast, file_signatures, ima_dm
from keylime.ima.file_signatures import ImaKeyrings

logger = keylime_logging.init_logging("ima")


# The version of the allowlist format that is supported by this keylime release
ALLOWLIST_CURRENT_VERSION = 5


class IMA_POLICY_GENERATOR:
    Unknown = 0
    EmptyAllowList = 1
    CompatibleAllowList = 2
    LegacyAllowList = 3


# A correctly-formatted empty allowlist.
#
# IMA allowlists of versions older than 5 will not have the "log_hash_alg"
# parameter. Hard-coding it to "sha1" is perfectly fine, and the fact one
# specifies a different algorithm on the kernel command line (e.g., ima_hash=sha256)
# does not affect normal operation of Keylime, since it does not validate the
# hash algorithm received from agent's IMA runtime measurements.
# The only situation where this hard-coding would become a problem is if and when
# the kernel maintainers decide to use a different algorithm for template-hash.
EMPTY_ALLOWLIST = {
    "meta": {
        "version": ALLOWLIST_CURRENT_VERSION,
        "generator": IMA_POLICY_GENERATOR.EmptyAllowList,
        "checksum": "",
    },
    "release": 0,
    "hashes": {},
    "keyrings": {},
    "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1"},
}

IMA_POLICY_CURRENT_VERSION = 1
EMPTY_IMA_POLICY = {
    "meta": {
        "version": IMA_POLICY_CURRENT_VERSION,
    },
    "release": 0,
    "digests": {},
    "excludes": [],
    "keyrings": {},
    "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1", "dm_policy": None},
    "ima-buf": {},
    "verification-keys": "",
}


class IMAMeasurementList:
    """IMAMeasurementList models the IMA measurement lists's last known
    two numbers of entries and filesizes
    """

    instance = None
    entries: Set[Tuple[int, int]]

    @staticmethod
    def get_instance() -> "IMAMeasurementList":
        """Return a singleton"""
        if not IMAMeasurementList.instance:
            IMAMeasurementList.instance = IMAMeasurementList()
        return IMAMeasurementList.instance

    def __init__(self) -> None:
        """Constructor"""
        self.entries = set()
        self.reset()

    def reset(self) -> None:
        """Reset the variables"""
        self.entries = set()

    def update(self, num_entries: int, filesize: int) -> None:
        """Update the number of entries and current filesize of the log."""
        if len(self.entries) > 256:
            for entry in self.entries:
                self.entries.discard(entry)
                break
        self.entries.add((num_entries, filesize))

    def find(self, nth_entry: int) -> Tuple[int, int]:
        """Find the closest entry to the n-th entry and return its number
        and filesize to seek to, return 0, 0 if nothing was found.
        """
        best = (0, 0)
        for entry in self.entries:
            if entry[0] > best[0] and entry[0] <= nth_entry:
                best = entry
        return best


def read_measurement_list(ima_log_file: TextIO, nth_entry: int) -> Tuple[Optional[str], int, int]:
    """Read the IMA measurement list starting from a given entry.
    The entry may be of any value 0 <= entry <= entries_in_log where
    entries_in_log + 1 indicates that the client wants to read the next entry
    once available. If the entry is outside this range, the function will
    automatically read from the 0-th entry.
    This function returns the measurement list and the entry from where it
    was read and the current number of entries in the file.
    """
    IMAML = IMAMeasurementList.get_instance()
    ml = None

    # Try to find the closest entry to the nth_entry
    num_entries, filesize = IMAML.find(nth_entry)

    if not ima_log_file:
        IMAML.reset()
        nth_entry = 0
        logger.warning("IMA measurement list not available: %s", config.IMA_ML)
    else:
        ima_log_file.seek(filesize)
        filedata = ima_log_file.read()
        # filedata now corresponds to starting list at entry number 'IMAML.num_entries'
        # find n-th entry and determine number of total entries in file now
        offset = 0
        while True:
            try:
                if nth_entry == num_entries:
                    ml = filedata[offset:]
                o = filedata.index("\n", offset)
                offset = o + 1
                num_entries += 1
            except ValueError:
                break
        # IMAML.filesize corresponds to position for entry number 'IMAML.num_entries'
        IMAML.update(num_entries, filesize + offset)

        # Nothing found? User request beyond next-expected entry.
        # Start over with entry 0. This cannot recurse again.
        if ml is None:
            return read_measurement_list(ima_log_file, 0)

    return ml, nth_entry, num_entries


def _validate_ima_ng(
    exclude_regex: Optional[Pattern[str]],
    allowlist: Optional[Dict[str, Any]],
    digest: ast.Digest,
    path: ast.Name,
    hash_types: str = "hashes",
) -> Failure:
    failure = Failure(Component.IMA, ["validation", "ima-ng"])
    if allowlist is not None:
        if exclude_regex is not None and exclude_regex.match(path.name):
            logger.debug("IMA: ignoring excluded path %s", path)
            return failure

        accept_list = allowlist[hash_types].get(path.name, None)
        if accept_list is None:
            logger.warning("File not found in allowlist: %s", path.name)
            failure.add_event("not_in_allowlist", f"File not found in allowlist: {path.name}", True)
            return failure

        if codecs.encode(digest.hash, "hex").decode("utf-8") not in accept_list:
            logger.warning(
                "Hashes for file %s don't match %s not in %s",
                path.name,
                codecs.encode(digest.hash, "hex").decode("utf-8"),
                accept_list,
            )
            failure.add_event(
                "allowlist_hash",
                {
                    "message": "Hash not in allowlist found",
                    "got": codecs.encode(digest.hash, "hex").decode("utf-8"),
                    "expected": accept_list,
                },
                True,
            )
            return failure

    return failure


def _validate_ima_sig(
    exclude_regex: Optional[Pattern[str]],
    ima_keyrings: Optional[file_signatures.ImaKeyrings],
    allowlist: Optional[Dict[str, Any]],
    digest: ast.Digest,
    path: ast.Name,
    signature: ast.Signature,
) -> Failure:
    failure = Failure(Component.IMA, ["validator", "ima-sig"])
    valid_signature = False
    if ima_keyrings and signature:

        if exclude_regex is not None and exclude_regex.match(path.name):
            logger.debug("IMA: ignoring excluded path %s", path.name)
            return failure

        if not ima_keyrings.integrity_digsig_verify(signature.data, digest.hash, digest.algorithm):
            logger.warning("signature for file %s is not valid", path.name)
            failure.add_event("invalid_signature", f"signature for file {path.name} is not valid", True)
            return failure

        valid_signature = True
        logger.debug("signature for file %s is good", path)

    # If there is also an allowlist verify the file against that but only do this if:
    # - we did not evaluate the signature (valid_siganture = False)
    # - the signature is valid and the file is also in the allowlist
    if (
        allowlist is not None
        and allowlist.get("hashes") is not None
        and ((allowlist["hashes"].get(path.name, None) is not None and valid_signature) or not valid_signature)
    ):
        # We use the normal ima_ng validator to validate hash
        return _validate_ima_ng(exclude_regex, allowlist, digest, path)

    # If we don't have a allowlist and don't have a keyring we just ignore the validation.
    if ima_keyrings is None:
        return failure

    if not valid_signature:
        failure.add_event("invalid_signature", f"signature for file {path.name} could not be validated", True)
    return failure


def _validate_ima_buf(
    exclude_regex: Optional[Pattern[str]],
    allowlist: Optional[Dict[str, Any]],
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
        if allowlist:
            ignored_keyrings = allowlist.get("ima", {}).get("ignored_keyrings", [])

        if "*" not in ignored_keyrings and path.name not in ignored_keyrings:
            failure = _validate_ima_ng(exclude_regex, allowlist, digest, path, hash_types="keyrings")
            if not failure:
                # Add the key only now that it's validated (no failure)
                if ima_keyrings is not None:
                    ima_keyrings.add_pubkey_to_keyring(pubkey, path.name, keyidv2=keyidv2)
    # Check if this is a device mapper entry only if we have a validator for that
    elif dm_validator is not None and path.name in dm_validator.valid_names:
        failure = dm_validator.validate(digest, path, data)
    else:
        # handling of generic ima-buf entries that for example carry a hash in the buf field
        failure = _validate_ima_ng(exclude_regex, allowlist, digest, path, hash_types="ima-buf")

    # Anything else evaluates to true for now
    return failure


def _process_measurement_list(
    agentAttestState: AgentAttestState,
    lines: List[str],
    hash_alg: Hash,
    lists: Optional[Union[str, Dict[str, Any]]] = None,
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
        pcrval_bytes = codecs.decode(pcrval.encode("utf-8"), "hex")

    if lists is not None:
        if isinstance(lists, str):
            lists = json.loads(lists)
            assert isinstance(lists, dict)
        allow_list = lists["allowlist"]
        exclude_list = lists["exclude"]
    else:
        allow_list = None
        exclude_list = None

    ima_log_hash_alg = algorithms.Hash.SHA1
    if allow_list is not None:
        try:
            ima_log_hash_alg = algorithms.Hash(allow_list["ima"]["log_hash_alg"])
        except ValueError:
            logger.warning(
                "Specified IMA log hash algorithm %s is not a valid algorithm! Defaulting to SHA1.",
                allow_list["ima"]["log_hash_alg"],
            )

    if boot_aggregates and allow_list:
        if "boot_aggregate" not in allow_list["hashes"]:
            allow_list["hashes"]["boot_aggregate"] = []
        for alg in boot_aggregates.keys():
            for val in boot_aggregates[alg]:
                if val not in allow_list["hashes"]["boot_aggregate"]:
                    allow_list["hashes"]["boot_aggregate"].append(val)

    compiled_regex, err_msg = validators.valid_exclude_list(exclude_list)
    if err_msg:
        # This should not happen as the exclude list has already been validated
        # by the verifier before acceping it. This is a safety net just in case.
        err_msg += " Exclude list will be ignored."
        logger.error(err_msg)

    # Setup device mapper validation
    dm_validator = None
    if allow_list is not None:
        dm_policy = allow_list["ima"]["dm_policy"]

        if dm_policy is not None:
            dm_validator = ima_dm.DmIMAValidator(dm_policy)
            dm_state = agentAttestState.get_ima_dm_state()
            # Only load state when using incremental attestation
            if agentAttestState.get_next_ima_ml_entry() != 0:
                dm_validator.state_load(dm_state)

    ima_validator = ast.Validator(
        {
            ast.ImaSig: functools.partial(_validate_ima_sig, compiled_regex, ima_keyrings, allow_list),
            ast.ImaNg: functools.partial(_validate_ima_ng, compiled_regex, allow_list),
            ast.Ima: functools.partial(_validate_ima_ng, compiled_regex, allow_list),
            ast.ImaBuf: functools.partial(_validate_ima_buf, compiled_regex, allow_list, ima_keyrings, dm_validator),
        }
    )

    # Iterative attestation may send us no log [len(lines) == 1]; compare last know PCR 10 state
    # against current PCR state.
    # Since IMA's append to the log and PCR extend as well as Keylime's retrieval of the quote, reading
    # of PCR 10 and retrieval of the log are not atomic, we may get a quote that does not yet take into
    # account the next-appended measurements' [len(lines) >= 2] PCR extension(s). In fact, the value of
    # the PCR may lag the log by several entries.
    if not found_pcr:
        found_pcr = running_hash == pcrval_bytes

    for linenum, line in enumerate(lines):
        # remove only the newline character, as there can be the space
        # as the delimiter character followed by an empty field at the
        # end
        line = line.strip("\n")
        if line == "":
            continue

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

    # Check if any validators failed
    if sum(errors.values()) > 0:
        error_msg = "IMA ERRORS: Some entries couldn't be validated. Number of failures in modes: "
        error_msg += ", ".join([f"{k.__name__ } {v}" for k, v in errors.items()])
        logger.error("%s.", error_msg)

    return codecs.encode(running_hash, "hex").decode("utf-8"), failure


def process_measurement_list(
    agentAttestState: AgentAttestState,
    lines: List[str],
    lists: Optional[Union[str, Dict[str, Any]]] = None,
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
            lists=lists,
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


def update_allowlist(allowlist: Dict[str, Any]) -> Dict[str, Any]:
    """Update the allowlist to the latest version adding default values for missing fields"""
    allowlist["meta"]["version"] = ALLOWLIST_CURRENT_VERSION

    # version 2 added 'keyrings'
    if "keyrings" not in allowlist:
        allowlist["keyrings"] = {}
    # version 3 added 'ima' map with 'ignored_keyrings'
    if "ima" not in allowlist:
        allowlist["ima"] = {}
    if not "ignored_keyrings" in allowlist["ima"]:
        allowlist["ima"]["ignored_keyrings"] = []
    # version 4 added 'ima-buf'
    if "ima-buf" not in allowlist:
        allowlist["ima-buf"] = {}
    # version 5 added 'log_hash_alg'
    if not "log_hash_alg" in allowlist["ima"]:
        allowlist["ima"]["log_hash_alg"] = "sha1"
    # version 6 added 'dm_policy'
    if "dm_policy" not in allowlist["ima"]:
        allowlist["ima"]["dm_policy"] = None

    return allowlist


def process_ima_policy(allowlist: Dict[str, Any], exclude: List[str]) -> Dict[str, Any]:
    # Pull in default config values if not specified
    if allowlist is None:
        allowlist = read_allowlist()
    else:
        allowlist = update_allowlist(allowlist)

    if allowlist["ima"]["dm_policy"] is not None:
        logger.info("IMA device mapper support is still experimental and might change in the future!")

    if exclude is None:
        exclude = read_excllist()

    if allowlist["hashes"].get("boot_aggregate") is None:
        logger.warning("No boot_aggregate value found in allowlist, adding an empty one")
        allowlist["hashes"]["boot_aggregate"] = ["0" * 40, "0" * 64]

    for excl in exclude:
        # remove commented out lines
        if excl.startswith("#"):
            exclude.remove(excl)
        # don't allow empty lines in exclude list, it will match everything
        if excl == "":
            exclude.remove(excl)

    return {"allowlist": allowlist, "exclude": exclude}


# Read allowlist files from disk, validate signatures and checksums, and prepare for sending.
# Does not process exclusion lists.
def read_allowlist(
    alist: Optional[str] = None,
    checksum: Optional[str] = "",
    al_sig_file: Optional[str] = None,
    al_key_file: Optional[str] = None,
) -> Dict[str, Any]:

    al_key = b""
    al_sig = b""

    # If user only wants signatures then an allowlist is not required
    if alist is None or alist == "":
        alist_bytes = json.dumps(copy.deepcopy(EMPTY_ALLOWLIST)).encode()

    elif isinstance(alist, str):
        # Purposefully die if path doesn't exist
        with open(alist, "rb") as alist_f:
            logger.debug("Loading allowlist from %s", alist)
            alist_bytes = alist_f.read()

    else:
        raise Exception("Invalid allowlist provided")

    # verify file signature if needed
    if al_sig_file and al_key_file:
        logger.debug(
            "Loading signature (%s) and key (%s) and checking against allowlist (%s)", al_sig_file, al_key_file, alist
        )
        with open(al_key_file, "rb") as key_f:
            al_key = key_f.read()
        with open(al_sig_file, "rb") as sig_f:
            al_sig = sig_f.read()
        if signing.verify_signature(al_key, al_sig, alist_bytes):
            logger.debug("Allowlist passed signature verification")
        else:
            raise Exception(
                f"Allowlist signature verification failed comparing allowlist ({alist}) against sig_file ({al_sig_file})"
            )

    sha256 = hashlib.sha256()
    sha256.update(alist_bytes)
    calculated_checksum = sha256.hexdigest()
    logger.debug("Loaded allowlist from %s with checksum %s", alist, calculated_checksum)

    if checksum:
        if checksum == calculated_checksum:
            logger.debug("Allowlist passed checksum validation")
        else:
            raise Exception(
                f"Checksum of allowlist does not match! Expected {checksum}, Calculated {calculated_checksum}"
            )
    else:
        logger.debug("Allowlist did not have a checksum provided, will add calculated checksum to bundle")
        checksum = calculated_checksum
    # Return artifacts as a JSON bundle, ready for sending
    bundle = {
        "ima_policy": base64.b64encode(alist_bytes).decode(),
        "key": base64.b64encode(al_key).decode(),
        "sig": base64.b64encode(al_sig).decode(),
        "checksum": checksum,
        "excllist": [],
    }

    return bundle


class SignatureValidationError(Exception):
    def __init__(self, message: str, code: int) -> None:
        self.message = message
        self.code = code
        super().__init__(self.message)


# Reads allowlist bundles sent to the verifier, validates them, and processes them. Returns an allowlist.
def unbundle_ima_policy(allowlist_bundle: Dict[str, Any], verify: bool = True) -> Dict[str, Any]:
    allowlist_raw = base64.b64decode(allowlist_bundle["ima_policy"])

    # Verify allowlist signatures if set to enforce
    if verify:
        if not allowlist_bundle.get("sig"):
            raise SignatureValidationError(
                message="Verifier is enforcing signature validation, but no signature was provided.", code=405
            )
        if not allowlist_bundle.get("key"):
            raise SignatureValidationError(
                message="Verifier is enforcing signature validation, but no public key was provided.", code=405
            )

        allowlist_sig = base64.b64decode(cast(bytes, allowlist_bundle.get("sig")))
        allowlist_sig_key = base64.b64decode(cast(bytes, allowlist_bundle.get("key")))

        if not signing.verify_signature(allowlist_sig_key, allowlist_sig, allowlist_raw):
            raise SignatureValidationError(message="Signature verification for allowlist failed!", code=401)
        logger.info("Allowlist signature validation passed.")

    return canonicalize_allowlist(allowlist_raw, allowlist_bundle["checksum"])


# Manipulates allowlists into database-ready format.
def canonicalize_allowlist(alist_bytes: bytes, checksum: str = "") -> Dict[str, Any]:
    # if the first non-whitespace character in the file is '{' treat it as the new JSON format
    alist_raw = alist_bytes.decode("utf-8")
    p = re.compile(r"^\s*{")
    if p.match(alist_raw):
        logger.debug("Reading allow list as JSON format")
        alist = json.loads(alist_raw)

        # verify it's the current version
        if "meta" in alist and "version" in alist["meta"]:
            version = alist["meta"]["version"]
            if int(version) <= ALLOWLIST_CURRENT_VERSION:
                logger.debug("Allowlist has compatible version %s", version)
            else:
                # in the future we will support multiple versions and convert between them,
                # but for now there is only one
                raise Exception("Allowlist has unsupported version {version}")
        else:
            logger.debug("Allowlist does not specify a version. Assuming current version %s", ALLOWLIST_CURRENT_VERSION)

        alist["meta"]["generator"] = IMA_POLICY_GENERATOR.CompatibleAllowList
    else:
        # convert legacy format into new structured format
        logger.debug("Converting legacy allowlist format to JSON")

        alist = copy.deepcopy(EMPTY_ALLOWLIST)
        alist["meta"]["timestamp"] = str(datetime.datetime.now())
        alist["meta"]["generator"] = IMA_POLICY_GENERATOR.LegacyAllowList
        if checksum:
            alist["meta"]["checksum"] = checksum

        for line in alist_raw.splitlines():
            line = line.strip()
            if len(line) == 0:
                continue

            pieces = line.split(None, 1)
            if not len(pieces) == 2:
                logger.warning("Line in AllowList does not consist of hash and file path: %s", line)
                continue

            (checksum_hash, path) = pieces

            if path.startswith("%keyring:"):
                entrytype = "keyrings"
                path = path[len("%keyring:") :]  # remove leading '%keyring:' from path to get keyring name
            else:
                entrytype = "hashes"

            if path in alist[entrytype]:
                alist[entrytype][path].append(checksum_hash)
            else:
                alist[entrytype][path] = [checksum_hash]

    return update_allowlist(alist)


def ima_policy_db_contents(ima_policy_name: str, ima_policy: str, tpm_policy: str = "") -> Dict[str, Any]:
    """Assembles an ima policy dictionary to be written on the database"""
    ima_policy_db_format: Dict[str, Any] = {}
    ima_policy_db_format["name"] = ima_policy_name

    # TODO: This was required to ensure e2e CI tests pass
    if ima_policy == "{}":
        ima_policy_db_format["ima_policy"] = None
    else:
        ima_policy_db_format["ima_policy"] = ima_policy

    ima_policy_bytes = ima_policy.encode()
    ima_policy_dict = json.loads(ima_policy)
    if "allowlist" in ima_policy_dict:
        if "meta" in ima_policy_dict["allowlist"]:
            if "generator" in ima_policy_dict["allowlist"]["meta"]:
                ima_policy_db_format["generator"] = ima_policy_dict["allowlist"]["meta"]["generator"]
            else:
                ima_policy_db_format["generator"] = IMA_POLICY_GENERATOR.Unknown

            if "timestamp" in ima_policy_dict["allowlist"]["meta"]:
                meta_timestamp = ima_policy_dict["allowlist"]["meta"]["timestamp"]
                # If a unique timestamp, injected by the verifier, is found within the
                # (potentially large) IMA policy string, remove it to ensure
                # matching checksums for identical policies.
                ima_policy_bytes = ima_policy.replace(meta_timestamp, "").encode()

    if tpm_policy:
        ima_policy_db_format["tpm_policy"] = tpm_policy

    ima_policy_db_format["checksum"] = hashlib.sha256(ima_policy_bytes).hexdigest()

    return ima_policy_db_format


def read_excllist(exclude_path: Optional[str] = None) -> List[str]:
    excl_list = []
    if exclude_path and os.path.exists(exclude_path):
        with open(exclude_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or len(line) == 0:
                    continue
                excl_list.append(line)

        logger.debug("Loaded exclusion list from %s: %s", exclude_path, excl_list)

    return excl_list
