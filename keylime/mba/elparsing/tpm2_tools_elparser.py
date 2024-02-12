import base64
import binascii
import hashlib
import re
import tempfile
import typing
from typing import Any, Dict, Optional

from packaging.version import Version

from keylime import cmd_exec, config, keylime_logging
from keylime.failure import Component, Failure

if typing.TYPE_CHECKING:
    from keylime.mba.mba import MBAgg, MBLog, MBPCRDict

logger = keylime_logging.init_logging("elparsing")


def bootlog_parse(
    mb_measurement_list: Optional[str], hash_alg: str
) -> typing.Tuple["MBPCRDict", "MBAgg", "MBLog", Failure]:
    """
    Parse the measured boot log and return its object and the state of the PCRs
    :param mb_measurement_list: The measured boot measurement list
    :param hash_alg: the hash algorithm that should be used for the PCRs
    :returns: Returns a map of the state of the PCRs, measured boot data object and True for success
    and False in case an error occurred
    """
    failure = Failure(Component.MEASURED_BOOT, ["parser"])
    if mb_measurement_list:
        failure_mb, mb_measurement_data = _parse_bootlog(mb_measurement_list)
        if not mb_measurement_data:
            failure.merge(failure_mb)
            logger.error("Unable to parse measured boot event log. Check previous messages for a reason for error.")
            return {}, None, {}, failure
        log_pcrs = mb_measurement_data.get("pcrs")
        if not isinstance(log_pcrs, dict):
            logger.error("Parse of measured boot event log has unexpected value for .pcrs: %r", log_pcrs)
            failure.add_event("invalid_pcrs", {"got": log_pcrs}, True)
            return {}, None, {}, failure
        pcr_hashes = log_pcrs.get(hash_alg)
        if (not isinstance(pcr_hashes, dict)) or not pcr_hashes:
            logger.error("Parse of measured boot event log has unexpected value for .pcrs.%s: %r", hash_alg, pcr_hashes)
            failure.add_event("invalid_pcrs_hashes", {"got": pcr_hashes}, True)
            return {}, None, {}, failure
        boot_aggregates = mb_measurement_data.get("boot_aggregates")
        if (not isinstance(boot_aggregates, dict)) or not boot_aggregates:
            logger.error(
                "Parse of measured boot event log has unexpected value for .boot_aggragtes: %r", boot_aggregates
            )
            failure.add_event("invalid_boot_aggregates", {"got": boot_aggregates}, True)
            return {}, None, {}, failure
        return pcr_hashes, boot_aggregates, mb_measurement_data, failure
    return {}, None, {}, failure


def _parse_bootlog(log_b64: str) -> typing.Tuple[Failure, typing.Optional[Dict[str, Any]]]:
    """Parse and enrich a BIOS boot log
    The input is the base64 encoding of a binary log.
    The output is the result of parsing and applying other conveniences."""
    failure = Failure(Component.MEASURED_BOOT, ["parser"])
    log_bin = base64.b64decode(log_b64, validate=True)
    try:
        failure_mb, result = parse_binary_bootlog(log_bin)
        if failure_mb:
            failure.merge(failure_mb)
            result = None
    except binascii.Error:
        failure.add_event("log.base64decode", "Measured boot log could not be decoded", True)
        result = None
    return failure, result


def parse_binary_bootlog(log_bin: bytes) -> typing.Tuple[Failure, typing.Optional[Dict[str, Any]]]:
    """Parse and enrich a BIOS boot log
    The input is the binary log.
    The output is the result of parsing and applying other conveniences."""
    failure = Failure(Component.MEASURED_BOOT, ["parser"])
    with tempfile.NamedTemporaryFile() as log_bin_file:
        log_bin_file.write(log_bin)
        log_bin_file.seek(0)
        log_bin_filename = log_bin_file.name
        retDict_tpm2 = cmd_exec.run(cmd=["tpm2_eventlog", "--eventlog-version=2", log_bin_filename], raiseOnError=False)
    log_parsed_strs = retDict_tpm2["retout"]
    if len(retDict_tpm2["reterr"]) > 0:
        failure.add_event(
            "tpm2_eventlog.warning",
            {"context": "tpm2_eventlog exited with warnings", "data": str(retDict_tpm2["reterr"])},
            True,
        )
        return failure, None
    log_parsed_data = config.yaml_to_dict(log_parsed_strs, add_newlines=False, logger=logger)
    if log_parsed_data is None:
        failure.add_event("yaml", "yaml output of tpm2_eventlog could not be parsed!", True)
        return failure, None
    # pylint: disable=import-outside-toplevel
    try:
        from keylime.mba.elparsing import tpm_bootlog_enrich
    except Exception as e:
        logger.error("Could not load tpm_bootlog_enrich (which depends on %s): %s", config.LIBEFIVAR, str(e))
        failure.add_event(
            "bootlog_enrich",
            f"Could not load tpm_bootlog_enrich (which depends on {config.LIBEFIVAR}): {str(e)}",
            True,
        )
        return failure, None
    # pylint: enable=import-outside-toplevel
    tpm_bootlog_enrich.enrich(log_parsed_data)
    __stringify_pcr_keys(log_parsed_data)
    __add_boot_aggregate(log_parsed_data)
    __unescape_eventlog(log_parsed_data)
    return failure, log_parsed_data


def __stringify_pcr_keys(log: Dict[str, Dict[str, Dict[str, str]]]) -> None:
    """Ensure that the PCR indices are strings

    The YAML produced by `tpm2_eventlog`, when loaded by the yaml module,
    uses integer keys in the dicts holding PCR contents.  That does not
    correspond to any JSON data.  This method ensures those keys are
    strings.
    The log is untrusted because it ultimately comes from an untrusted
    source and has been processed by software that has had bugs."""

    if (not isinstance(log, dict)) or "pcrs" not in log:
        return
    old_pcrs = log["pcrs"]
    if not isinstance(old_pcrs, dict):
        return
    new_pcrs = {}
    for hash_alg, cells in old_pcrs.items():
        if not isinstance(cells, dict):
            new_pcrs[hash_alg] = cells
            continue
        new_pcrs[hash_alg] = {str(index): val for index, val in cells.items()}
    log["pcrs"] = new_pcrs
    return


def __unescape_eventlog(log: Dict) -> None:  # type: ignore
    """
    Newer versions of tpm2-tools escapes the YAML output and including the trailing null byte.
    See: https://github.com/tpm2-software/tpm2-tools/commit/c78d258b2588aee535fd17594ad2f5e808056373
    This converts it back to an unescaped string.
    Example:
        '"MokList\\0"' -> 'MokList'
    """
    tpm2_tools_version = tpm2_tools_getversion()
    # only versions 5.2, 5.3, 5.4 and beyond have null terminated strings that should be "unescaped"
    if tpm2_tools_version in ["unknown", "3.2", "4.0", "4.2"]:
        return

    escaped_chars = [
        ("\0", "\\0"),
        ("\a", "\\a"),
        ("\b", "\\b"),
        ("\t", "\\t"),
        ("\v", "\\v"),
        ("\f", "\\f"),
        ("\r", "\\r"),
        ("\x1b", "\\e"),
        ("'", "\\'"),
        ("\\", "\\\\"),
    ]

    def recursive_unescape(data):  # type: ignore
        if isinstance(data, str) and data:
            # Older tpm2-tools versions quote add additional quotes
            if Version(tpm2_tools_version) < Version("5.6") and data.startswith('"') and data.endswith('"'):
                data = data[1:-1]
            for orig, escaped in escaped_chars:
                data = data.replace(escaped, orig)
            if data.endswith("\0"):
                data = data[:-1]
        elif isinstance(data, dict):
            for key, value in data.items():
                data[key] = recursive_unescape(value)  # type: ignore
        elif isinstance(data, list):
            for pos, item in enumerate(data):
                data[pos] = recursive_unescape(item)  # type: ignore
        return data

    recursive_unescape(log)  # type: ignore


def __add_boot_aggregate(log: Dict[str, Any]) -> None:
    """Scan the boot event log and calculate possible boot aggregates.

    Hashes are calculated for both sha1 and sha256,
    as well as for 8 or 10 participant PCRs.

    Technically the sha1/10PCR combination is unnecessary, since it has no
    implementation.

    Error conditions caused by improper string formatting etc. are
    ignored. The current assumption is that the boot event log PCR
    values are in decimal encoding, but this is liable to change."""
    if (not isinstance(log, dict)) or "pcrs" not in log:
        return
    log["boot_aggregates"] = {}
    for hashalg in log["pcrs"].keys():
        log["boot_aggregates"][hashalg] = []
        for maxpcr in [8, 10]:
            try:
                hashclass = getattr(hashlib, hashalg)
                h = hashclass()
                for pcrno in range(0, maxpcr):
                    pcrstrg = log["pcrs"][hashalg][str(pcrno)]
                    pcrhex = f"{pcrstrg:0{h.digest_size*2}x}"
                    h.update(bytes.fromhex(pcrhex))
                log["boot_aggregates"][hashalg].append(h.hexdigest())
            except Exception:
                pass


_tpm2_tools_version = None


def tpm2_tools_getversion() -> str:
    global _tpm2_tools_version
    if _tpm2_tools_version is not None:
        return _tpm2_tools_version
    retDict = cmd_exec.run(cmd=["tpm2_startup", "--version"], raiseOnError=False)
    code = retDict["code"]
    output = "".join(config.convert(retDict["retout"]))
    if code != 0:
        logger.error("unable to run tpm2_startup")
        _tpm2_tools_version = "unknown"
        return _tpm2_tools_version

    # Extract the `version="x.x.x"` from tools
    version_str_ = re.search(r'version="([^"]+)"', output)
    if version_str_ is None:
        logger.error("unable to determine TPM2-TOOLS version")
        _tpm2_tools_version = "unknown"
        return _tpm2_tools_version
    version_str = version_str_.group(1)
    # Extract the full semver release number.
    tools_version = version_str.split("-")
    if Version(tools_version[0]) >= Version("5.6"):
        _tpm2_tools_version = "5.6"
        return _tpm2_tools_version
    if Version(tools_version[0]) >= Version("5.4") or (
        # Also mark first git version that introduces the change to the tpm2_eventlog format as 5.4
        # See: https://github.com/tpm2-software/tpm2-tools/commit/c78d258b2588aee535fd17594ad2f5e808056373
        Version(tools_version[0]) == Version("5.3")
        and len(tools_version) > 1
        and int(tools_version[1]) >= 24
    ):
        _tpm2_tools_version = "5.4"
        return _tpm2_tools_version
    if Version(tools_version[0]) == Version("5.2"):
        # GA, MaS: experimentally found that version 5.2 of the tpm2_eventlog package produces output with
        # zero-terminated strings on both centos 9 and Ubuntu 22.04.
        # Adding a separate category for tpm2_tools_version so we can control whether strings are unescaped properly.
        _tpm2_tools_version = "5.2"
        return _tpm2_tools_version
    if Version(tools_version[0]) >= Version("4.2"):
        _tpm2_tools_version = "4.2"
        return _tpm2_tools_version
    if Version(tools_version[0]) >= Version("4.0.0"):
        _tpm2_tools_version = "4.0"
        return _tpm2_tools_version
    if Version(tools_version[0]) >= Version("3.2.0"):
        _tpm2_tools_version = "3.2"
        return _tpm2_tools_version
    logger.error("TPM2-TOOLS Version %s is not supported.", tools_version[0])
    _tpm2_tools_version = "unknown"
    return _tpm2_tools_version


toolversion = tpm2_tools_getversion()
if toolversion == "unknown":
    raise ValueError("TPM2-TOOLS: version cannot be determined or unsupported")
logger.debug("mba.elparser.tpm2_tools_elparser: TPM2-TOOLS %s detected.", toolversion)
