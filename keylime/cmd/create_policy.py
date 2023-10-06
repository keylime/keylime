#!/usr/bin/env python3

""" Create a JSON allowlist/policy from given files as input """

import argparse
import binascii
import collections
import copy
import datetime
import gzip
import json
import multiprocessing
import os
import pathlib
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat import backends

try:
    import rpm

except ModuleNotFoundError:
    rpm = None

from keylime.common import validators
from keylime.ima import file_signatures, ima
from keylime.ima.types import RuntimePolicyType
from keylime.signing import verify_signature_from_file
from keylime.types import PathLike_str

IMA_MEASUREMENT_LIST = "/sys/kernel/security/ima/ascii_runtime_measurements"
IGNORED_KEYRINGS: List[str] = []

# Estimation of a RPM header size
HEADER_SIZE = 24 * 1024


def is_x509_cert(bindata: bytes) -> bool:
    """Determine whether the given bindata are a x509 cert"""
    try:
        x509.load_der_x509_certificate(bindata, backend=backends.default_backend())
        return True
    except ValueError:
        return False


def process_flat_allowlist(allowlist_file: str, hashes_map: Dict[str, List[str]]) -> Tuple[Dict[str, List[str]], int]:
    """Process a flat allowlist file"""
    ret = 0
    try:
        with open(allowlist_file, "r", encoding="utf-8") as fobj:
            while True:
                line = fobj.readline()
                if not line:
                    break
                line = line.strip()
                if len(line) == 0:
                    continue
                pieces = line.split(None, 1)
                if not len(pieces) == 2:
                    print(f"Skipping line that was split into {len(pieces)} parts, expected 2: {line}", file=sys.stderr)
                    continue

                (checksum_hash, path) = pieces
                hashes_map.setdefault(path, []).append(checksum_hash)
    except (PermissionError, FileNotFoundError) as ex:
        print(f"An error occurred while accessing the allowlist: {ex}", file=sys.stderr)
        ret = 1
    return hashes_map, ret


def get_hashes_from_measurement_list(
    ima_measurement_list_file: str, hashes_map: Dict[str, List[str]]
) -> Tuple[Dict[str, List[str]], int]:
    """Get the hashes from the IMA measurement list file"""
    ret = 0
    try:
        with open(ima_measurement_list_file, "r", encoding="utf-8") as fobj:
            while True:
                line = fobj.readline()
                if not line:
                    break
                pieces = line.split(" ")
                if len(pieces) < 5:
                    print(
                        f"Skipping line that was split into {len(pieces)} pieces, expected at least 5: {line}",
                        file=sys.stderr,
                    )
                    continue
                if pieces[2] not in ["ima-sig", "ima-ng"]:
                    continue
                # FIXME: filenames with spaces may be problematic
                checksum_hash = pieces[3].split(":")[1]
                path = pieces[4].rstrip("\n")
                hashes_map.setdefault(path, []).append(checksum_hash)
    except (PermissionError, FileNotFoundError) as ex:
        print(f"An error occurred: {ex}", file=sys.stderr)
        ret = 1
    return hashes_map, ret


def process_ima_buf_in_measurement_list(
    ima_measurement_list_file: str,
    ignored_keyrings: List[str],
    get_keyrings: bool,
    keyrings_map: Dict[str, List[str]],
    get_ima_buf: bool,
    ima_buf_map: Dict[str, List[str]],
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], int]:
    """Process ima-buf entries and get the keyrings map from key-related entries
    and ima_buf map from the rest
    """
    ret = 0
    try:
        with open(ima_measurement_list_file, "r", encoding="utf-8") as fobj:
            while True:
                line = fobj.readline()
                if not line:
                    break
                # FIXME: filenames with spaces may be problematic
                pieces = line.split(" ")
                if len(pieces) != 6:
                    print(
                        f"Skipping line that was split into {len(pieces)} pieces, expected 6: {line}",
                        file=sys.stderr,
                    )
                    continue
                if pieces[2] not in ["ima-buf"]:
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
                if bindata and is_x509_cert(bindata):
                    if path in ignored_keyrings or not get_keyrings:
                        continue

                    keyrings_map.setdefault(path, []).append(checksum_hash)
                    continue

                if get_ima_buf:
                    ima_buf_map.setdefault(path, []).append(checksum_hash)
    except (PermissionError, FileNotFoundError) as ex:
        print(f"An error occurred: {ex}", file=sys.stderr)
        ret = 1
    return keyrings_map, ima_buf_map, ret


def process_signature_verification_keys(verification_keys: List[str], policy: RuntimePolicyType) -> RuntimePolicyType:
    """Add the given keys (x509 certificates) to keyring"""

    verification_key_list = None
    if verification_keys:
        if policy.get("verification-keys"):
            keyring = file_signatures.ImaKeyring().from_string(policy["verification-keys"])
            if not keyring:
                print("Could not create IMAKeyring from JSON", file=sys.stderr)
        else:
            keyring = file_signatures.ImaKeyring()
        if keyring:
            for key in verification_keys:
                try:
                    pubkey, keyidv2 = file_signatures.get_pubkey_from_file(key)
                    if not pubkey:
                        print(f"File '{key}' is not a file with a key", file=sys.stderr)
                    else:
                        keyring.add_pubkey(pubkey, keyidv2)
                except ValueError as e:
                    print(f"File '{key}' does not have a supported key: {e}", file=sys.stderr)
            verification_key_list = keyring.to_string()

    if verification_key_list:
        policy["verification-keys"] = verification_key_list

    return policy


def process_exclude_list_file(exclude_list_file: str, excludes: List[str]) -> Tuple[List[str], int]:
    """Add the contents of the IMA exclude list file to the given list"""
    ret = 0
    try:
        with open(exclude_list_file, "r", encoding="utf-8") as fobj:
            while True:
                line = fobj.readline()
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                _, err_msg = validators.valid_exclude_list([line])
                if err_msg:
                    print(f"Bad IMA exclude list rule '{line}': {err_msg}")
                    return [], 1

                excludes.append(line)
    except (PermissionError, FileNotFoundError) as ex:
        print(f"An error occurred: {ex}", file=sys.stderr)
        ret = 1
    return excludes, ret


def analyze_rpm_pkg(pkg: PathLike_str) -> Dict[str, List[str]]:
    """Analyze a single RPM package."""
    if rpm is None:
        raise Exception("rpm module is not available")
    ts = rpm.TransactionSet()
    ts.setVSFlags(rpm.RPMVSF_MASK_NOSIGNATURES | rpm.RPMVSF_MASK_NODIGESTS)

    with open(pkg, "rb") as f:
        hdr = ts.hdrFromFdno(f)
    # Symbolic links in IMA are resolved before the measured,
    # registering the final linked name in the logs
    info = {f.name: [f.digest] for f in rpm.files(hdr) if f.digest != "0" * 64}

    return info


def analyze_rpm_pkg_url(url: str) -> Dict[str, List[Any]]:
    """Analyze a single RPM package from its URL."""

    # To fetch the header we can emulate rpmReadPackageFile, but this
    # seems to require multiple reads.  This simplified algorithm read
    # first a sizeable blob, adjusted from the median of some repo
    # analysis, and if the hdrFromFdno fails, try to expand it
    # iteratively.

    if rpm is None:
        raise Exception("rpm module is not available")

    # Hide errors while fetching partial headers
    rpm.setLogFile(open(os.devnull, "wb"))  # pylint: disable=consider-using-with

    print(f"Fetching header for {url}", file=sys.stderr)

    blob = b""
    chunk_size = HEADER_SIZE
    while True:
        with tempfile.TemporaryFile() as f:
            range_ = f"{len(blob)}-{len(blob) + chunk_size - 1}"
            req = urllib.request.Request(url, headers={"Range": f"bytes={range_}"})
            with urllib.request.urlopen(req) as resp:
                blob += resp.read()

            f.write(blob)
            f.seek(0)

            ts = rpm.TransactionSet()
            ts.setVSFlags(rpm.RPMVSF_MASK_NOSIGNATURES | rpm.RPMVSF_MASK_NODIGESTS)
            try:
                hdr = ts.hdrFromFdno(f)
                break
            except Exception:
                chunk_size = max(1024, int(chunk_size / 2))

    # Symbolic links in IMA are resolved before the measured,
    # registering the final linked name in the logs
    info = {f.name: [f.digest] for f in rpm.files(hdr) if f.digest != "0" * 64}

    return info


def analize_local_repo(
    repo: pathlib.Path, hash_map: Dict[str, List[str]], jobs: Optional[int] = None
) -> Tuple[Dict[str, List[str]], int]:
    repomd_xml = repo / "repodata" / "repomd.xml"
    if not repomd_xml.exists():
        print(f"{repomd_xml} cannot be found", file=sys.stderr)
        # TODO - remove Go idioms
        return {}, 1

    repomd_asc = repo / "repodata" / "repomd.xml.asc"
    if repomd_asc.exists():
        repomd_key = repo / "repodata" / "repomd.xml.key"
        if not repomd_key.exists():
            print(f"Error. Key file {repomd_key} missing", file=sys.stderr)
            return {}, 1

        try:
            verify_signature_from_file(repomd_key, repomd_xml, repomd_asc, "Repository metadata")
        except Exception:
            print("Error. Invalid dignature. Untrusted repository", file=sys.stderr)
            return {}, 1
    else:
        print("Warning. Unsigned repository. Continuing the RPM scanning", file=sys.stderr)

    jobs = jobs if jobs else multiprocessing.cpu_count()

    # Analyze all the RPMs in parallel
    with multiprocessing.Pool(jobs) as pool:
        packages = pool.map(analyze_rpm_pkg, repo.glob("**/*.rpm"))

    hash_map.update(dict(collections.ChainMap(*packages)))

    return hash_map, 0


def _get(url: str) -> Optional[str]:
    try:
        with urllib.request.urlopen(url) as resp:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                shutil.copyfileobj(resp, f)
                return f.name
    except urllib.error.HTTPError:
        return None


def _get_filelists_ext_xml(repo: str, repomd_xml: str) -> Optional[str]:
    root = ET.parse(repomd_xml).getroot()
    location = root.find(
        "./{http://linux.duke.edu/metadata/repo}data[@type='filelists-ext']/{http://linux.duke.edu/metadata/repo}location"
    )
    return urllib.parse.urljoin(repo, location.attrib["href"]) if location is not None else None


def _get_rpm_urls(repo: str, repomd_xml: str) -> List[str]:
    root = ET.parse(repomd_xml).getroot()
    location = root.find(
        "./{http://linux.duke.edu/metadata/repo}data[@type='primary']/{http://linux.duke.edu/metadata/repo}location"
    )
    if location is None:
        print("Error. Primary location tag not found", file=sys.stderr)
        return []

    print("Generating package list from repo ...", file=sys.stderr)
    primary_xml = urllib.parse.urljoin(repo, location.attrib["href"])
    primary_xml_tmp = _get(primary_xml)
    if primary_xml_tmp is None:
        print("Error. Primary XML file cannot be downloaded", file=sys.stderr)
        return []

    root = ET.parse(gzip.open(primary_xml_tmp))
    os.remove(primary_xml_tmp)

    locations = root.findall(
        "./{http://linux.duke.edu/metadata/common}package[@type='rpm']"
        "/{http://linux.duke.edu/metadata/common}location"
    )

    return [urllib.parse.urljoin(repo, l.attrib["href"]) for l in locations]


def analize_remote_repo(
    repo: str, hash_map: Dict[str, List[str]], jobs: Optional[int] = None
) -> Tuple[Dict[str, List[str]], int]:
    # Make the repo ends with "/", so we can be considered as a base URL
    repo = repo if repo.endswith("/") else f"{repo}/"

    repomd_xml = urllib.parse.urljoin(repo, "repodata/repomd.xml")
    repomd_xml_tmp = _get(repomd_xml)
    if not repomd_xml_tmp:
        print(f"{repomd_xml} cannot be found", file=sys.stderr)
        return {}, 1

    repomd_asc = urllib.parse.urljoin(repo, "repodata/repomd.xml.asc")
    repomd_asc_tmp = _get(repomd_asc)
    if repomd_asc_tmp:
        repomd_key = urllib.parse.urljoin(repo, "repodata/repomd.xml.key")
        repomd_key_tmp = _get(repomd_key)
        if not repomd_key_tmp:
            print(f"Error. Key file {repomd_key} missing", file=sys.stderr)
            os.remove(repomd_xml_tmp)
            return {}, 1

        try:
            verify_signature_from_file(repomd_key_tmp, repomd_xml_tmp, repomd_asc_tmp, "Repository metadata")
        except Exception:
            print("Error. Invalid dignature. Untrusted repository", file=sys.stderr)
            os.remove(repomd_xml_tmp)
            os.remove(repomd_asc_tmp)
            os.remove(repomd_key_tmp)
            return {}, 1

        os.remove(repomd_asc_tmp)
        os.remove(repomd_key_tmp)
    else:
        print("Warning. Unsigned repository. Continuing the RPM scanning", file=sys.stderr)

    # Check if this repo contains the filelists-ext.xml metadata
    filelists_ext_xml = _get_filelists_ext_xml(repo, repomd_xml_tmp)
    if filelists_ext_xml:
        filelists_ext_xml_tmp = _get(filelists_ext_xml)
        if not filelists_ext_xml_tmp:
            print(f"{filelists_ext_xml} cannot be found", file=sys.stderr)
            os.remove(repomd_xml_tmp)
            return {}, 1

        root = ET.parse(gzip.open(filelists_ext_xml_tmp))
        os.remove(filelists_ext_xml_tmp)
        os.remove(repomd_xml_tmp)

        files = root.findall(".//{http://linux.duke.edu/metadata/filelists-ext}file[@hash]")
        for f in files:
            if not f.text:
                continue
            v = hash_map.get(f.text, [])
            v.append(f.attrib["hash"])
            hash_map[f.text] = v

        return hash_map, 0

    # If not, use the slow method
    print("Warning. filelist-ext.xml not present in the repo", file=sys.stderr)
    rpms = _get_rpm_urls(repo, repomd_xml_tmp)
    os.remove(repomd_xml_tmp)

    # The default job selection is a bit weird.  The issue is that
    # seems that librpm can be not always thread safe, so we can use a
    # single thread (asyncio) or multiple process.  To avoid change
    # all the stack, I go for synchronous functions but with many
    # process.  In the future we can move all to asyncio.
    jobs = jobs if jobs else (multiprocessing.cpu_count() * 8)

    # Analyze all the RPMs in parallel
    with multiprocessing.Pool(jobs) as pool:
        packages = pool.map(analyze_rpm_pkg_url, rpms)

    hash_map.update(dict(collections.ChainMap(*packages)))

    return hash_map, 0


def main() -> None:
    """main"""
    parser = argparse.ArgumentParser(description="This is tool for adding items to a Keylime's IMA runtime policy")
    parser.add_argument(
        "-B",
        "--base-policy",
        action="store",
        dest="base_policy",
        help="Merge new data into the given JSON runtime policy",
    )
    parser.add_argument(
        "-k", "--keyrings", action="store_true", dest="get_keyrings", help="Create keyrings policy entries"
    )
    parser.add_argument(
        "-b",
        "--ima-buf",
        action="store_true",
        dest="get_ima_buf",
        help="Process ima-buf entries other than those related to keyrings",
    )
    parser.add_argument("-a", "--allowlist", action="store", dest="allowlist", help="Use given plain-text allowlist")
    parser.add_argument(
        "-m",
        "--ima-measurement-list",
        action="store",
        dest="ima_measurement_list",
        default=IMA_MEASUREMENT_LIST,
        help="Use given IMA measurement list for hash, keyring, and critical "
        f"data extraction rather than {IMA_MEASUREMENT_LIST}; use /dev/null for "
        "an empty list",
    )
    parser.add_argument(
        "-i",
        "--ignored-keyrings",
        action="append",
        dest="ignored_keyrings",
        default=IGNORED_KEYRINGS,
        help="Ignored the given keyring; this option may be passed multiple times",
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        dest="output",
        help="File to write JSON policy into; default is to print to stdout",
    )
    parser.add_argument(
        "--no-hashes", action="store_true", dest="no_hashes", help="Do not add any hashes to the policy"
    )
    parser.add_argument(
        "-A",
        "--add-ima-signature-verification-key",
        action="append",
        dest="ima_signature_keys",
        default=[],
        help="Add the given IMA signature verification key to the Keylime-internal 'tenant_keyring'; "
        "the key should be an x509 certificate in DER or PEM format but may also be a public or "
        "private key file; this option may be passed multiple times",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        action="store",
        dest="exclude_list_file",
        help="An IMA exclude list file whose contents will be added to the policy",
    )
    parser.add_argument("-l", "--local-repo", metavar="REPO", type=pathlib.Path, help="Local repo directory")
    parser.add_argument("-r", "--remote-repo", metavar="URL", help="Remote repo directory")

    args = parser.parse_args()

    policy = copy.deepcopy(ima.EMPTY_RUNTIME_POLICY)

    ret = 0

    if args.base_policy:
        try:
            with open(args.base_policy, "r", encoding="utf-8") as fobj:
                basepol = fobj.read()
            base_policy: RuntimePolicyType = json.loads(basepol)

            try:
                ima.validate_runtime_policy(base_policy)
            except ima.ImaValidationError as ex:
                print(f"Base policy is not a valid runtime policy: {ex}", file=sys.stderr)
                sys.exit(1)

            # Cherry-pick from base policy what is supported and merge into policy
            policy["digests"] = base_policy.get("digests", {})
            policy["excludes"] = base_policy.get("excludes", [])
            policy["keyrings"] = base_policy.get("keyrings", {})
            policy["ima-buf"] = base_policy.get("ima-buf", {})
            ignored_keyrings = base_policy.get("ima", {}).get("ignored_keyrings", [])
            policy["ima"]["ignored_keyrings"] = ignored_keyrings
            policy["verification-keys"] = base_policy.get("verification-keys", "")
        except (PermissionError, FileNotFoundError) as ex:
            print(f"An error occurred while loading the policy: {ex}", file=sys.stderr)
            ret = 1
        except json.decoder.JSONDecodeError as ex:
            print(f"An error occurred while converting the policy to a JSON object: {ex}", file=sys.stderr)
            ret = 1
    if ret:
        sys.exit(ret)

    if (args.local_repo or args.remote_repo) and rpm is None:
        print('To analyze RPM repositories the "rpm" Python module is required', file=sys.stderr)
        sys.exit(1)

    # Add the digests map either from the allowlist, a repo, or the
    # IMA measurement list.
    if args.allowlist:
        policy["digests"], ret = process_flat_allowlist(args.allowlist, policy["digests"])
    elif args.local_repo:
        policy["digests"], ret = analize_local_repo(args.local_repo, policy["digests"])
    elif args.remote_repo:
        policy["digests"], ret = analize_remote_repo(args.remote_repo, policy["digests"])
    elif not args.no_hashes:
        policy["digests"], ret = get_hashes_from_measurement_list(args.ima_measurement_list, policy["digests"])
    if ret:
        sys.exit(ret)

    if args.exclude_list_file:
        policy["excludes"], ret = process_exclude_list_file(args.exclude_list_file, policy["excludes"])
    if ret:
        sys.exit(ret)

    policy["ima"]["ignored_keyrings"].extend(args.ignored_keyrings)

    if args.get_keyrings or args.get_ima_buf:
        policy["keyrings"], policy["ima-buf"], ret = process_ima_buf_in_measurement_list(
            args.ima_measurement_list,
            policy["ima"]["ignored_keyrings"],
            args.get_keyrings,
            policy["keyrings"],
            args.get_ima_buf,
            policy["ima-buf"],
        )

    if ret:
        sys.exit(ret)

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
        print(f"Base policy is not a valid runtime policy: {ex}", file=sys.stderr)
        sys.exit(1)

    jsonpolicy = json.dumps(policy)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fobj:
                fobj.write(jsonpolicy)
        except (PermissionError, FileNotFoundError) as ex:
            print(f"An error occurred while writing the policy: %{ex}", file=sys.stderr)
            ret = 1
    else:
        print(jsonpolicy)

    sys.exit(ret)


if __name__ == "__main__":
    main()
