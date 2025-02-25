"""
Module to assist with creating runtime policies.
"""

import argparse
import binascii
import datetime
import json
import os
import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib import util
from typing import TYPE_CHECKING, Any, Dict, List, Optional, TextIO, Tuple

import psutil

from keylime.common import algorithms, validators
from keylime.ima import file_signatures, ima
from keylime.ima.types import RuntimePolicyType
from keylime.models.base import Certificate
from keylime.policy import initrd
from keylime.policy.logger import Logger
from keylime.policy.utils import merge_lists, merge_maplists

_has_rpm = util.find_spec("rpm") is not None

rpm_repo: Any
if _has_rpm:
    from keylime.policy import rpm_repo


if TYPE_CHECKING:
    # FIXME: how to make mypy and pylint happy here?
    _SubparserType = argparse._SubParsersAction[argparse.ArgumentParser]  # pylint: disable=protected-access
else:
    _SubparserType = Any

logger = Logger().logger()

# We use /dev/null to indicate an empty ima measurement list.
EMPTY_IMA_MEASUREMENT_LIST = "/dev/null"
IMA_MEASUREMENT_LIST = "/sys/kernel/security/ima/ascii_runtime_measurements"

IGNORED_KEYRINGS: List[str] = []
DEFAULT_FILE_DIGEST_ALGORITHM = algorithms.Hash.SHA256

# This is to follow IMA default
# See in keylime/ima/ima.py
DEFAULT_IMA_TEMPLATE_DIGEST_ALGORITHM = algorithms.Hash.SHA1

# This is used to indicate that the algorithm guessing identified a valid output
# length, but it corresponds to more than one supported algorithm
SHA256_OR_SM3 = "sha256_or_sm3_256"

# This is used to indicate that the algorithm guessing could not identify the
# algorithm from the output length
INVALID_ALGORITHM = "invalid"

BASE_EXCLUDE_DIRS: List[str] = [
    "/sys",
    "/run",
    "/proc",
    "/lost+found",
    "/dev",
    "/media",
    "/snap",
    "/mnt",
    "/var",
    "/tmp",
]


def exclude_dirs_based_on_rootfs(dirs_to_exclude: List[str]) -> List[str]:
    """
    Build a list of directories to exclude, as they don't match the root filesystem.

    :param dirs_to_exclude: list of directories to exclude
    :return: a list of strings, that contains directories we need to exclude
    """
    rootfs = None
    to_exclude = []
    # First we identify the root filesystem
    disk_part = psutil.disk_partitions(all=True)
    for pp in disk_part:
        if pp.mountpoint == "/":
            rootfs = pp.fstype
            break

    # Now we select mountpoints to exclude
    for pp in disk_part:
        if pp.fstype != rootfs:
            to_exclude.append(pp.mountpoint)
            logger.debug(
                "exclude_dirs_based_on_rootfs(): excluding %s (fstype %s); rootfs: %s",
                pp.mountpoint,
                pp.fstype,
                rootfs,
            )

    trimmed_dirs = []
    # Finally, let's trim this list down based on the existing
    # dirs_to_exclude.
    for dir_e in to_exclude:
        matched = False
        for cur in dirs_to_exclude:
            if dir_e.startswith(cur):
                matched = True
                logger.debug("exclude_dirs_based_on_rootfs(): %s already covered by %s; skipping", dir_e, cur)
                continue
        if not matched:
            trimmed_dirs.append(dir_e)
    logger.debug("exclude_dirs_based_on_rootfs(): excluded dirs: %s", trimmed_dirs)
    return trimmed_dirs


def _calculate_digest(prefix: str, fpath: str, alg: str, remove_prefix: bool) -> Tuple[bool, str, str]:
    """
    Filter the specified file to decide if we should calculate its digest.

    This method should skip non-files (e.g. sockets) and directories,
    as well as files not owned by root (uid 0).

    The return is a tuple with 3 values:
    1) a boolean indicating the success of the operation
       to calculate its checksum, as well as
    2) the file path path (with the prefix removed, if required), and
    3) its associated digest.

    :param prefix: str indicating the path prefix, the "root" directory for the file
    :param fpath: str inficating the path for the file
    :param alg: int, digest algorithm
    :param remove_prefix: boolean that indicates whether the displayed file should have its prefix removed
    :return: Tuple of boolean, str and str, indicating whether this method calculated the digest, the file name and its digest, respectively
    """

    # Let's take care of removing the prefix, if requested.
    fkey = fpath
    if remove_prefix and (str(prefix) != "/"):
        fkey = fkey[len(str(prefix)) :]

    # IMA replaces spaces with underscores in the log, so we do
    # that here as well, for them to match.
    fkey = fkey.replace(" ", "_")

    return True, fkey, algorithms.Hash(alg).file_digest(fpath)


def _get_all_files(
    root_dir: str, prefix: str, dirs_to_exclude: Optional[List[str]] = None, only_owned_by_root: bool = False
) -> List[str]:
    """Find all files inside a directory recursively, skipping the directories
    marked to be excluded and files not owned by root, if requested.
    It is expected that root_dir and prefix are absolute paths."""

    if not dirs_to_exclude:
        dirs_to_exclude = []

    paths = set()
    subdirs = []
    with os.scandir(root_dir) as it:
        for entry in it:
            # Skip symlinks
            if entry.is_symlink():
                continue

            # If the entry is a file, add to the set of paths
            if entry.is_file():
                # Skipping files not not owned by root (uid 0), if requested.
                if only_owned_by_root:
                    try:
                        st = os.stat(entry.path, follow_symlinks=False)
                        if st.st_uid != 0:
                            continue
                    except FileNotFoundError:
                        logger.debug("Could not find '%s', skipping", entry.path)
                        continue

                paths.add(entry.path)
                continue

            # For directories, add the entry to the subdirectories
            if entry.is_dir():
                relpath = entry.path
                if prefix != "/" and entry.path.startswith(prefix):
                    relpath = entry.path[len(prefix) :]

                # Skip directories marked to be excluded from the search
                if relpath in dirs_to_exclude:
                    logger.debug("Skipping '%s' that matches a directory path to exclude", entry.path)
                    continue

                subdirs.append(entry.path)

    for d in subdirs:
        paths.update(_get_all_files(d, prefix, dirs_to_exclude, only_owned_by_root))

    return list(paths)


def path_digests(
    *fdirpath: str,
    alg: str = DEFAULT_FILE_DIGEST_ALGORITHM,
    dirs_to_exclude: Optional[List[str]] = None,
    digests: Optional[Dict[str, List[str]]] = None,
    remove_prefix: bool = True,
    only_owned_by_root: bool = False,
    match_rootfs: bool = False,
) -> Dict[str, List[str]]:
    """
    Calculate the digest of every file under the specified directory.

    :param *fdirpath: the directory that contains the files to calculate their digests
    :param alg: the algorithm to use for the digests. The default is SHA-256
    :param dirs_to_exclude: a list of directories that should be excluded from the checksum calculation
    :param digests: the map of files and their set of digests that will be filled by this method
    :param remove_prefix: a flag to indicate whether the files should have their prefixes removed when added to the resulting map
    :param only_owned_by_root: a flag to indicate it should calculate the digests only for files owned by root. Default is False
    :param match_rootfs: a flag to indicate we want files to match the filesystem of the root fs
    :return: a mapping of a file (str) with a set of checksums (str)
    """
    if digests is None:
        digests = {}

    absfpath = os.path.abspath(str(*fdirpath))
    if not os.path.isdir(absfpath):
        logger.error("Invalid path, %s is not a directory", absfpath)
        return digests

    # Let's first check if the root is not marked to be excluded.
    if dirs_to_exclude is None:
        dirs_to_exclude = []

    if match_rootfs:
        dirs_to_exclude.extend(exclude_dirs_based_on_rootfs(dirs_to_exclude))

    # Get the paths to all files contained in the directory, recursively
    paths = _get_all_files(absfpath, absfpath, dirs_to_exclude, only_owned_by_root)

    logger.debug("obtained %d paths", len(paths))

    futures = []
    with ThreadPoolExecutor() as executor:
        for p in paths:
            futures.append(
                executor.submit(
                    _calculate_digest,
                    absfpath,
                    pathlib.Path(p).as_posix(),
                    alg,
                    remove_prefix,
                )
            )

        for f in as_completed(futures):
            try:
                ok, fkey, fdigest = f.result()
                if ok:
                    if fkey not in digests:
                        digests[fkey] = []
                    digests[fkey].append(fdigest)
            except Exception:
                logger.debug("Failed to calculate a digest")
                continue

    return digests


def print_digests_legacy_format(digests: Dict[str, List[str]], outfile: TextIO) -> None:
    """
    Print the digest dict using the legacy allowlist format.

    Helper to print the digests dictionary in the format
    used by the old allowlist, which is basically the output
    of the sha256sum utility, i.e. <digest>  <file>

    :param digests: a dictionary that maps a file with a set of checksums
    :return: None
    """
    # Print the boot_aggregate first, if available
    boot_agg_fname = "boot_aggregate"
    if boot_agg_fname in digests:
        for digest in digests[boot_agg_fname]:
            print(f"{digest}  {boot_agg_fname}", file=outfile)

    for fname, fdigests in digests.items():
        if fname == boot_agg_fname:
            continue
        for digest in fdigests:
            print(f"{digest}  {fname}", file=outfile)


def process_ima_sig_ima_ng_line(line: str) -> Tuple[str, str, str, bool]:
    """
    Process a single line "ima", "ima-ng" and "ima-sig" IMA log .

    :param line: str that has the line to be processed
    :return: a tuple containing 3 strings and a bool. The strings are, in
             order: 1) the hash algorithm used, 2) the checksum, 3) either
             the file path or signature, depending on the template, and 4)
             a boolean indicating whether the method succeeded
    """
    ret = ("", "", "", False)
    if not line:
        return ret

    pieces = line.split(" ")
    if len(pieces) < 5:
        errmsg = f"Skipping line that was split into {len(pieces)} pieces, expected at least 5: {line}"
        logger.debug(errmsg)
        return ret

    if pieces[2] not in ("ima-sig", "ima-ng", "ima"):
        errmsg = f"skipping line that uses a template ({pieces[2]}) not in ('ima-sig', 'ima-ng', 'ima'): {line}"
        logger.debug(errmsg)
        return ret

    csum_hash = pieces[3].split(":")

    alg = ""
    csum = ""
    if len(csum_hash) == 2:
        alg = csum_hash[0]
        csum = csum_hash[1]

        # Check if the algorithm is one of the supported algorithms
        if not algorithms.Hash.is_recognized(alg):
            return ret

        # Check that the length of the digest matches the expected length
        if len(csum) != algorithms.Hash(alg).hexdigest_len():
            return ret

    # Old "ima" template.
    else:
        csum = csum_hash[0]
        # Lets attempt to detect the alg by len.
        alg = _get_digest_algorithm_from_hex(csum)
        if alg == INVALID_ALGORITHM:
            errmsg = f"skipping line that using old 'ima' template because it was not possible to identify the hash alg: {line}"
            logger.debug(errmsg)
            return ret

    path = pieces[4].rstrip("\n")
    return alg, csum, path, True


def boot_aggregate_parse(line: str) -> Tuple[str, str]:
    """
    Parse the boot aggregate from the provided line.

    :param line: str with the line to be parsed
    :return: tuple with two values, the algorithm used and the digest of the
             boot aggregate
    """
    alg, digest, fpath, ok = process_ima_sig_ima_ng_line(line)
    if not ok or fpath != "boot_aggregate":
        return INVALID_ALGORITHM, ""
    return alg, digest


def boot_aggregate_from_file(
    ascii_runtime_file: str = IMA_MEASUREMENT_LIST,
) -> Tuple[str, str]:
    """
    Return the boot aggregate indicated in the specified file.

    :param ascii_runtime_file: a string indicating the file where we should read the boot aggregate from. The default is /sys/kernel/security/ima/ascii_runtime_measurements.
    :return: str, the boot aggregate
    """
    line = ""
    with open(ascii_runtime_file, "r", encoding="UTF-8") as f:
        line = f.readline().strip("\n")

    return boot_aggregate_parse(line)


def list_initrds(basedir: str = "/boot") -> List[str]:
    """
    Return a list of initrds found in the indicated base dir.

    :param basedir: str, the directory where to find the initrds. Default is /boot
    :return: a list of filenames starting with "initr"
    """
    initrds = []
    for f in os.scandir(basedir):
        if f.is_file() and pathlib.Path(f.path).name.startswith("initr"):
            initrds.append(pathlib.Path(f.path).as_posix())
    return initrds


def process_flat_allowlist(allowlist_file: str, hashes_map: Dict[str, List[str]]) -> Tuple[Dict[str, List[str]], bool]:
    """Process a flat allowlist file."""
    ret = True
    try:
        with open(allowlist_file, "r", encoding="UTF-8") as fobj:
            while True:
                line = fobj.readline()
                if not line:
                    break
                line = line.strip()
                if len(line) == 0:
                    continue
                pieces = line.split(None, 1)
                if not len(pieces) == 2:
                    logmsg = f"Skipping line that was split into {len(pieces)} parts, expected 2: {line}"
                    logger.debug(logmsg)
                    continue

                (checksum_hash, path) = pieces

                # IMA replaces spaces with underscores in the log, so we do
                # that here as well, for them to match.
                path = path.replace(" ", "_")
                hashes_map.setdefault(path, []).append(checksum_hash)
    except (PermissionError, FileNotFoundError) as ex:
        errmsg = f"An error occurred while accessing the allowlist: {ex}"
        logger.error(errmsg)
        ret = False
    return hashes_map, ret


def get_arg_parser(create_parser: _SubparserType, parent_parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Perform the setup of the command-line arguments for this module."""
    runtime_p = create_parser.add_parser("runtime", help="create runtime policies", parents=[parent_parser])
    fs_group = runtime_p.add_argument_group("runtime policy from filesystem")

    if _has_rpm:
        repo_group = runtime_p.add_argument_group("runtime policy from repositories")
        repo_group.add_argument(
            "--local-rpm-repo", dest="local_rpm_repo", type=pathlib.Path, help="Local RPM repo directory"
        )
        repo_group.add_argument(
            "--remote-rpm-repo",
            dest="remote_rpm_repo",
            help="Remote RPM repo URL",
        )

    fs_group.add_argument(
        "--algo",
        dest="algo",
        choices=list(algorithms.Hash),
        required=False,
        help="checksum algorithm to be used. If not specified, it will attempt to use the same algorithm the boot aggregate uses or fallback to sha256, otherwise",
        default="",
    )
    fs_group.add_argument(
        "--ramdisk-dir",
        dest="ramdisk_dir",
        required=False,
        help="path to where the initrds are located, e.g.: /boot",
        default="",
    )
    fs_group.add_argument(
        "--rootfs",
        dest="rootfs",
        required=False,
        help="path to the root filesystem, e.g.: /",
        default="",
    )
    fs_group.add_argument(
        "-s",
        "--skip-path",
        dest="skip_path",
        required=False,
        help="comma-separated list of directories; files found there will not have their checksums calculated",
        default="",
    )

    runtime_p.add_argument(
        "-o",
        "--output",
        dest="output",
        required=False,
        help="output file (defaults to stdout)",
        default="/dev/stdout",
    )
    runtime_p.add_argument(
        "-p",
        "--base-policy",
        dest="base_policy",
        required=False,
        help="Merge new data into the given JSON runtime policy",
        default="",
    )
    runtime_p.add_argument(
        "-k",
        "--keyrings",
        dest="get_keyrings",
        required=False,
        help="Create keyrings policy entries",
        action="store_true",
        default=False,
    )
    runtime_p.add_argument(
        "-b",
        "--ima-buf",
        dest="get_ima_buf",
        required=False,
        help="Process ima-buf entries other than those related to keyrings",
        action="store_true",
        default=False,
    )
    runtime_p.add_argument(
        "-a",
        "--allowlist",
        dest="allowlist",
        required=False,
        help="Read checksums from the given plain-text allowlist",
        default="",
    )
    runtime_p.add_argument(
        "-e",
        "--excludelist",
        dest="exclude_list_file",
        required=False,
        help="An IMA exclude list file whose contents will be added to the policy",
        default="",
    )
    runtime_p.add_argument(
        "-m",
        "--ima-measurement-list",
        dest="ima_measurement_list",
        required=False,
        nargs="?",
        help="Use an IMA measurement list for hash, keyring, and critical "
        f"data extraction. If a list is not specified, it uses {IMA_MEASUREMENT_LIST}. Use "
        f"{EMPTY_IMA_MEASUREMENT_LIST} for  an empty list.",
        default=EMPTY_IMA_MEASUREMENT_LIST,
    )
    runtime_p.add_argument(
        "--ignored-keyrings",
        dest="ignored_keyrings",
        action="append",
        required=False,
        help="Ignores the given keyring; this option may be passed multiple times",
        default=IGNORED_KEYRINGS,
    )
    runtime_p.add_argument(
        "--add-ima-signature-verification-key",
        action="append",
        dest="ima_signature_keys",
        default=[],
        help="Add the given IMA signature verification key to the Keylime-internal 'tenant_keyring'; "
        "the key should be an x509 certificate in DER or PEM format but may also be a public or "
        "private key file; this option may be passed multiple times",
    )
    runtime_p.add_argument(
        "--show-legacy-allowlist",
        dest="legacy_allowlist",
        help="Instead of the actual policy, display only the digests in the legacy allowlist format",
        action="store_true",
        default=False,
    )

    runtime_p.add_argument(
        "-v",
        "--verbose",
        help="Set log level to DEBUG; may be helpful when diagnosing issues",
        action="store_true",
        required=False,
        default=False,
    )

    runtime_p.set_defaults(func=create_runtime_policy)
    return runtime_p


def update_base_policy(base_policy_file: str) -> Optional[RuntimePolicyType]:
    """Update the base policy to the latest policy format"""

    policy = None

    try:
        with open(base_policy_file, "r", encoding="UTF-8") as fobj:
            basepol = fobj.read()

        # Load as a plain JSON without type. Do not assume it is a valid policy
        base_policy = json.loads(basepol)

        # Get an instance of the latest policy format to import the data
        policy = ima.empty_policy()

        # Cherry-pick from base policy what is supported and merge into policy
        policy["digests"] = merge_maplists(policy["digests"], base_policy.get("digests", {}))
        policy["excludes"] = merge_lists(policy["excludes"], base_policy.get("excludes", []))
        policy["keyrings"] = merge_maplists(policy["keyrings"], base_policy.get("keyrings", {}))
        policy["ima-buf"] = merge_maplists(policy["ima-buf"], base_policy.get("ima-buf", {}))

        policy["ima"]["log_hash_alg"] = base_policy.get("ima", {}).get(
            "log_hash_alg", DEFAULT_IMA_TEMPLATE_DIGEST_ALGORITHM
        )
        ignored_keyrings = base_policy.get("ima", {}).get("ignored_keyrings", [])
        policy["ima"]["ignored_keyrings"] = merge_lists(policy["ima"]["ignored_keyrings"], ignored_keyrings)
        policy["verification-keys"] = base_policy.get("verification-keys", "")
    except (PermissionError, FileNotFoundError) as ex:
        errmsg = f"An error occurred while loading the policy: {ex}"
        logger.error(errmsg)
        return None
    except json.decoder.JSONDecodeError as ex:
        errmsg = f"An error occurred while parsing a JSON object from file {base_policy_file}: {ex}"
        logger.error(errmsg)
        return None

    # Validate that the resulting policy is a valid policy
    try:
        ima.validate_runtime_policy(policy)
    except ima.ImaValidationError as ex:
        errmsg = f"Could not convert the provided base policy to a valid runtime policy: {ex}"
        logger.error(errmsg)
        return None

    return policy


def get_hashes_from_measurement_list(
    ima_measurement_list_file: str, hashes_map: Dict[str, List[str]]
) -> Tuple[Dict[str, List[str]], bool]:
    """Get the hashes from the IMA measurement list file."""
    ret = True
    try:
        with open(ima_measurement_list_file, "r", encoding="UTF-8") as fobj:
            while True:
                line = fobj.readline()
                if not line:
                    break
                pieces = line.split(" ")
                if len(pieces) < 5:
                    errmsg = f"Skipping line that was split into {len(pieces)} pieces, expected at least 5: {line}"
                    logger.debug(errmsg)
                    continue
                if pieces[2] not in ("ima-sig", "ima-ng"):
                    continue
                checksum_hash = pieces[3].split(":")[1]
                path = pieces[4].rstrip("\n")
                hashes_map.setdefault(path, []).append(checksum_hash)
    except (PermissionError, FileNotFoundError) as ex:
        errmsg = f"An error occurred: {ex}"
        logger.error(errmsg)
        ret = False
    return hashes_map, ret


def process_exclude_list_line(line: str) -> Tuple[str, bool]:
    """Validate an exclude list line."""
    if not line:
        return "", True

    _, validator_msg = validators.valid_exclude_list([line])
    if validator_msg:
        errmsg = f"Bad IMA exclude list rule '{line}': {validator_msg}"
        logger.warning(errmsg)
        return "", False

    return line, True


def process_exclude_list_file(exclude_list_file: str, excludes: List[str]) -> Tuple[List[str], bool]:
    """Add the contents of the IMA exclude list file to the given list."""
    ret = True
    try:
        with open(exclude_list_file, "r", encoding="UTF-8") as fobj:
            while True:
                line = fobj.readline()
                if not line:
                    break

                line, ok = process_exclude_list_line(line.strip())
                if not ok:
                    return [], False
                # Skip empty lines.
                if len(line) == 0:
                    continue

                excludes.append(line)
    except (PermissionError, FileNotFoundError) as ex:
        errmsg = f"An error occurred: {ex}"
        logger.error(errmsg)
        ret = False
    return excludes, ret


def get_rootfs_digests(
    rootfs: str, skip_path: Optional[str], hashes_map: Dict[str, List[str]], algo: str
) -> Dict[str, List[str]]:
    """Calculate digests for files under a directory."""

    abs_rootfs = os.path.abspath(rootfs)

    dirs_to_exclude = []

    # Preprocess the directories to skip, ignoring those outside the rootfs and
    # removing the prefix from those that are under the rootfs
    if skip_path:
        for d in skip_path.split(","):
            abs_d = os.path.abspath(d)

            if pathlib.PurePath(abs_rootfs).is_relative_to(abs_d):
                # Okay, nothing to do here, since the root is marked to be
                # skipped
                logger.debug("The rootfs %s is excluded because it matches or is within %s", abs_rootfs, abs_d)
                return {}

            if not pathlib.PurePath(d).is_relative_to(rootfs):
                logger.warning("Ignoring directory '%s' that should be skipped, but it is not under '%s'", d, rootfs)
            else:
                # Remove the prefix to make it consistent with other excluded
                # directories
                if abs_rootfs != "/" and abs_d.startswith(abs_rootfs):
                    dirs_to_exclude.append(abs_d[len(abs_rootfs) :])

    dirs_to_exclude.extend(BASE_EXCLUDE_DIRS)
    hashes_map = path_digests(
        rootfs,
        dirs_to_exclude=dirs_to_exclude,
        digests=hashes_map,
        alg=algo,
        only_owned_by_root=True,
        match_rootfs=True,
    )
    return hashes_map


def get_initrds_digests(initrd_dir: str, hashes_map: Dict[str, List[str]], algo: str) -> Dict[str, List[str]]:
    """Calculate digests for files from initrds from the given directory."""
    for initrd_file in list_initrds(initrd_dir):
        initrd_data = initrd.InitrdReader(initrd_file)
        hashes_map = path_digests(initrd_data.contents(), remove_prefix=True, digests=hashes_map, alg=algo)
    return hashes_map


def process_ima_buf_in_measurement_list(
    ima_measurement_list_file: str,
    ignored_keyrings: List[str],
    get_keyrings: bool,
    keyrings_map: Dict[str, List[str]],
    get_ima_buf: bool,
    ima_buf_map: Dict[str, List[str]],
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], bool]:
    """
    Process ima-buf entries.

    Process ima-buf entries and get the keyrings map from key-related entries
    and ima_buf map from the rest.
    """
    ret = True
    try:
        with open(ima_measurement_list_file, "r", encoding="UTF-8") as fobj:
            while True:
                line = fobj.readline()
                if not line:
                    break
                pieces = line.split(" ")
                if len(pieces) != 6:
                    errmsg = f"Skipping line that was split into {len(pieces)} pieces, expected 6: {line}"
                    logger.debug(errmsg)
                    continue
                if pieces[2] not in ("ima-buf"):
                    continue
                checksum_hash = pieces[3].split(":")[1]
                path = pieces[4]

                bindata = None
                try:
                    bindata = binascii.unhexlify(pieces[5].strip())
                except binascii.Error:
                    pass

                # check whether buf's bindata contains a key; if so, we will only
                # append it to 'keyrings', never to 'ima-buf'
                if bindata and Certificate().asn1_compliant(bindata):
                    if path in ignored_keyrings or not get_keyrings:
                        continue

                    keyrings_map.setdefault(path, []).append(checksum_hash)
                    continue

                if get_ima_buf:
                    ima_buf_map.setdefault(path, []).append(checksum_hash)
    except (PermissionError, FileNotFoundError) as ex:
        errmsg = f"An error occurred: {ex}"
        logger.error(errmsg)
        ret = False
    return keyrings_map, ima_buf_map, ret


def process_signature_verification_keys(verification_keys: List[str], policy: RuntimePolicyType) -> RuntimePolicyType:
    """Add the given keys (x509 certificates) to keyring."""
    if not verification_keys:
        return policy

    verification_key_list = None
    if policy.get("verification-keys"):
        keyring = file_signatures.ImaKeyring().from_string(policy["verification-keys"])
        if not keyring:
            logger.error("Could not create IMA Keyring from JSON")
    else:
        keyring = file_signatures.ImaKeyring()

    if keyring:
        for key in verification_keys:
            try:
                pubkey, keyidv2 = file_signatures.get_pubkey_from_file(key)
                if not pubkey:
                    errmsg = f"File '{key}' is not a file with a key"
                    logger.error(errmsg)
                else:
                    keyring.add_pubkey(pubkey, keyidv2)
            except ValueError as e:
                errmsg = f"File '{key}' does not have a supported key: {e}"
                logger.error(errmsg)

        verification_key_list = keyring.to_string()

    if verification_key_list:
        policy["verification-keys"] = verification_key_list

    return policy


def _get_digest_algorithm_from_hex(hexstring: str) -> str:
    """Try to identify the algorithm used to generate the provided value by length"""
    for alg in list(algorithms.Hash):
        if len(hexstring) == algorithms.Hash(alg).hexdigest_len():
            return str(alg)
    return INVALID_ALGORITHM


def _get_digest_algorithm_from_map_list(maplist: Dict[str, List[str]]) -> str:
    """Assuming all digests in the policy uses the same algorithm, get the first
    digest and try to obtain the algorithm from its length"""

    algo = INVALID_ALGORITHM
    if maplist:
        digest_list = next(iter(maplist.values()))
        if digest_list:
            digest = digest_list[0]
            if digest:
                algo = _get_digest_algorithm_from_hex(digest)
    return algo


def create_runtime_policy(args: argparse.Namespace) -> Optional[RuntimePolicyType]:
    """Create a runtime policy from the input arguments."""
    policy = None
    algo = None
    base_policy_algo = None
    allowlist_algo = None
    ima_measurement_list_algo = None

    allowlist_digests: Dict[str, List[str]] = {}
    ima_digests: Dict[str, List[str]] = {}
    rootfs_digests: Dict[str, List[str]] = {}
    ramdisk_digests: Dict[str, List[str]] = {}
    local_rpm_digests: Dict[str, List[str]] = {}
    remote_rpm_digests: Dict[str, List[str]] = {}

    # Adjust logging for verbose, if required.
    if args.verbose:
        Logger().enableVerbose()

    # If a base policy was provided, try to parse the file as JSON and import
    # the values to the current policy format.
    # Otherwise, use an empty policy as the base policy
    if args.base_policy:
        policy = update_base_policy(args.base_policy)
        if not policy:
            return None

        digests = policy.get("digests", {})

        # Try to get the digest algorithm from the lenght of the digest
        base_policy_algo = _get_digest_algorithm_from_map_list(digests)

        # If the guessed algorithm was SHA-256, it is actually ambiguous as it
        # could be also SM3_256. Set as SHA256_OR_SM3
        if base_policy_algo == algorithms.Hash.SHA256:
            base_policy_algo = SHA256_OR_SM3
    else:
        policy = ima.empty_policy()

    if args.algo:
        if not (args.ramdisk_dir or args.rootfs):
            logger.warning(
                "You need to specify at least one of --ramdisk-dir or --rootfs to use a custom digest algorithm"
            )

    if args.allowlist:
        allowlist_digests, ok = process_flat_allowlist(args.allowlist, {})
        if not ok:
            return None

        # Try to get the digest algorithm from the lenght of the digest
        allowlist_algo = _get_digest_algorithm_from_map_list(allowlist_digests)

        # If the guessed algorithm was SHA-256, it is actually ambiguous as it
        # could be also SM3_256. Set as SHA256_OR_SM3
        if allowlist_algo == algorithms.Hash.SHA256:
            allowlist_algo = SHA256_OR_SM3

    if args.ima_measurement_list != EMPTY_IMA_MEASUREMENT_LIST:
        ima_list = args.ima_measurement_list
        if ima_list is None:
            # Use the default list, when one is not specified.
            ima_list = IMA_MEASUREMENT_LIST

        logger.debug("Measurement list is %s", ima_list)
        if not os.path.isfile(ima_list):
            logger.warning("The IMA measurement list file '%s' does not seem to exist", ima_list)
            return None

        try:
            # If not set, try to get the digest algorithm from the boot_aggregate.
            ima_measurement_list_algo, _ = boot_aggregate_from_file(ima_list)
        except Exception:
            ima_measurement_list_algo = INVALID_ALGORITHM

        ima_digests = {}
        ima_digests, ok = get_hashes_from_measurement_list(ima_list, ima_digests)
        if not ok:
            return None

    if _has_rpm and rpm_repo:
        if args.local_rpm_repo:
            # FIXME: pass the IMA sigs as well.
            local_rpm_digests = {}
            local_rpm_digests, _imasigs, ok = rpm_repo.analyze_local_repo(
                args.local_rpm_repo, digests=local_rpm_digests
            )
            if not ok:
                return None
        if args.remote_rpm_repo:
            # FIXME: pass the IMA sigs as well.
            remote_rpm_digests = {}
            remote_rpm_digests, _imasigs, ok = rpm_repo.analyze_remote_repo(
                args.remote_rpm_repo, digests=remote_rpm_digests
            )
            if not ok:
                return None

    # Flag to indicate whether the operation should be aborted
    abort = False

    # Use the same digest algorithm used by the provided inputs, following the
    # priority order: --algo > base policy > allowlist > IMA measurement list
    for a, source in [
        (args.algo, "--algo option"),
        (base_policy_algo, "base policy"),
        (allowlist_algo, "allowlist"),
        (ima_measurement_list_algo, "IMA measurement list"),
    ]:
        if a == INVALID_ALGORITHM:
            logger.warning("Invalid digest algorithm found in the %s", source)
            abort = True
            continue

        # Skip unset options
        if not a:
            continue

        # If the algorithm was previously set, check it against the algorithm
        # from the current source
        if algo:
            if a != algo:
                if algo == SHA256_OR_SM3:
                    if a in [algorithms.Hash.SHA256, algorithms.Hash.SM3_256]:
                        algo = a
                        logger.debug("Using digest algorithm '%s' obtained from the %s", a, source)
                        continue

                logger.warning(
                    "The digest algorithm in the %s does not match the previously set '%s' algorithm", source, algo
                )
                abort = True
        else:
            if a not in algorithms.Hash:
                if a == SHA256_OR_SM3:
                    algo = a
                else:
                    logger.warning("Invalid digests algorithm %s in the %s", a, source)
                    abort = True
                continue

            algo = a

            if abort:
                continue

            logger.debug("Using digest algorithm '%s' obtained from the %s", a, source)

    if abort:
        logger.warning("Aborting operation")
        return None

    if not algo:
        logger.debug("Using default digest algorithm %s", DEFAULT_FILE_DIGEST_ALGORITHM)
        algo = DEFAULT_FILE_DIGEST_ALGORITHM

    if args.ramdisk_dir:
        ramdisk_digests = {}
        ramdisk_digests = get_initrds_digests(args.ramdisk_dir, ramdisk_digests, algo)

    if args.rootfs:
        rootfs_digests = {}
        rootfs_digests = get_rootfs_digests(args.rootfs, args.skip_path, rootfs_digests, algo)

    # Combine all obtained digests
    for digests in [
        allowlist_digests,
        ima_digests,
        rootfs_digests,
        ramdisk_digests,
        local_rpm_digests,
        remote_rpm_digests,
    ]:
        if not digests:
            continue
        policy["digests"] = merge_maplists(policy["digests"], digests)

    if args.exclude_list_file:
        policy["excludes"], ok = process_exclude_list_file(args.exclude_list_file, policy["excludes"])
        if not ok:
            return None

    policy["ima"]["ignored_keyrings"].extend(args.ignored_keyrings)
    if args.get_keyrings or args.get_ima_buf:
        policy["keyrings"], policy["ima-buf"], ok = process_ima_buf_in_measurement_list(
            args.ima_measurement_list,
            policy["ima"]["ignored_keyrings"],
            args.get_keyrings,
            policy["keyrings"],
            args.get_ima_buf,
            policy["ima-buf"],
        )
        if not ok:
            return None

    policy = process_signature_verification_keys(args.ima_signature_keys, policy)

    # Ensure we only have unique values in lists
    for key in ["digests", "ima-buf", "keyrings"]:
        policy[key] = {k: sorted(list(set(v))) for k, v in policy[key].items()}  # type: ignore

    policy["excludes"] = sorted(list(set(policy["excludes"])))
    policy["ima"]["ignored_keyrings"] = sorted(list(set(policy["ima"]["ignored_keyrings"])))

    policy["meta"]["generator"] = ima.RUNTIME_POLICY_GENERATOR.LegacyAllowList
    policy["meta"]["timestamp"] = str(datetime.datetime.now())

    try:
        ima.validate_runtime_policy(policy)
    except ima.ImaValidationError as ex:
        errmsg = f"Base policy is not a valid runtime policy: {ex}"
        logger.error(errmsg)
        return None

    try:
        with open(args.output, "w", encoding="UTF-8") as fobj:
            if args.legacy_allowlist:
                print_digests_legacy_format(policy["digests"], fobj)
            else:
                jsonpolicy = json.dumps(policy)
                fobj.write(jsonpolicy)
    except (PermissionError, FileNotFoundError) as ex:
        errmsg = f"An error occurred while writing the policy: %{ex}"
        logger.error(errmsg)
        return None

    return policy
