import argparse
import copy
import datetime
import json
import sys
from os.path import basename
from typing import Any, Dict, List, NoReturn, Optional

from keylime.ima import file_signatures, ima

PolicyDict = Dict[str, Any]

# pylint: disable=pointless-string-statement
"""
This script converts legacy Keylime policies into the unified, next-generation
IMA policy format. Both legacy allow/exclude lists as well as out-of-date IMA
policy formats are accepted.

Example usage:

To convert an allowlist and exclude list to an IMA policy at `keylime-policy.json`:

```
python convert_ima_policy.py -a <allowlist path> -e <exclude list path> -o keylime-policy.json
```

To convert an existing IMA policy to the latest version:

```
python convert_ima_policy.py -i <ima policy path> -o keylime-policy.json
```

To view help and see all available options:

```
python convert_ima_policy.py -h
```
"""

# Creates an IMA policy from provided legacy allowlist.
def convert_legacy_allowlist(allowlist_path: str) -> PolicyDict:
    with open(allowlist_path, "r", encoding="utf8") as f:
        alist_raw = f.read()

    # Attempt to load JSON, and convert the appropriate format
    try:
        alist_json = json.loads(alist_raw)
        print(f"{basename(allowlist_path)} appears to be JSON-formatted; converting to IMA policy")
        ima_policy = _convert_json_allowlist(alist_json)
    except Exception as _:
        print(
            f"{basename(allowlist_path)} is not JSON-formatted; attempting to convert to IMA policy from flat file format"
        )
        ima_policy = _convert_flat_format_allowlist(alist_raw)
    return ima_policy


# Converts JSON-format allowlist to JSON-format IMA policy
def _convert_json_allowlist(alist_json: PolicyDict) -> PolicyDict:
    ima_policy: PolicyDict = copy.deepcopy(ima.EMPTY_IMA_POLICY)
    ima_policy["meta"]["timestamp"] = str(datetime.datetime.now())
    ima_policy["meta"]["generator"] = ima.IMA_POLICY_GENERATOR.LegacyAllowList
    for key in ima_policy.keys():
        if key == "digests":
            digests = alist_json.get("hashes")
            if not digests:
                print("Allowlist does not have a valid hash list!")
            else:
                ima_policy[key] = alist_json["hashes"]
        elif key == "meta":
            # Skip old metadata
            continue
        else:
            to_migrate = alist_json.get(key)
            if not to_migrate:
                print(f"IMA policy field '{key}' not found in allowlist; using default value")
            else:
                ima_policy[key] = alist_json[key]
    return ima_policy


# Converts flat-format allowlist to JSON-format IMA policy
def _convert_flat_format_allowlist(alist_raw: str) -> PolicyDict:
    ima_policy: PolicyDict = copy.deepcopy(ima.EMPTY_IMA_POLICY)
    ima_policy["meta"]["timestamp"] = str(datetime.datetime.now())
    ima_policy["meta"]["generator"] = ima.IMA_POLICY_GENERATOR.LegacyAllowList

    lines = alist_raw.splitlines()
    for line_num, line in enumerate(lines):
        line = line.strip()
        if len(line) == 0:
            continue

        pieces = line.split(None, 1)
        if not len(pieces) == 2:
            print(f"Line #{line_num} in Allowlist does not consist of hash and file path: {line}")
            continue

        (checksum_hash, path) = pieces

        if path.startswith("%keyring:"):
            entrytype = "keyrings"
            path = path[len("%keyring:") :]  # remove leading '%keyring:' from path to get keyring name
        else:
            entrytype = "digests"

        if path in ima_policy[entrytype]:
            ima_policy[entrytype][path].append(checksum_hash)
        else:
            ima_policy[entrytype][path] = [checksum_hash]
    return ima_policy


# Updates an existing IMA policy to the latest version, and adds any provided input
def update_ima_policy(
    policy: PolicyDict, excludelist_path: Optional[str] = None, verification_keys: Optional[List[str]] = None
) -> PolicyDict:
    if policy["meta"]["version"] < ima.IMA_POLICY_CURRENT_VERSION:
        print(
            f"Provided policy has version {policy['meta']['version']}; latest policy has version {ima.IMA_POLICY_CURRENT_VERSION}. Updating to latest version."
        )
        updated_policy: PolicyDict = copy.deepcopy(ima.EMPTY_IMA_POLICY)
        updated_policy["meta"]["timestamp"] = str(datetime.datetime.now())
        updated_policy["meta"]["generator"] = ima.IMA_POLICY_GENERATOR.CompatibleAllowList
        for key in updated_policy.keys():
            if key == "meta":
                continue
            to_migrate = policy.get(key)
            if not to_migrate:
                print(f"IMA policy field '{key}' not found in existing IMA policy; using default value")
            else:
                updated_policy[key] = policy[key]
        policy = updated_policy

    excl_list = []
    if excludelist_path:
        with open(excludelist_path, "r", encoding="utf8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or len(line) == 0:
                    continue
                excl_list.append(line)

    verification_key_list = None
    if verification_keys:
        keyring = file_signatures.ImaKeyring().from_string(policy["ima_sign_verification_keys"])
        if not keyring:
            print("Could not create IMAKeyring from JSON")
        else:
            for key in verification_keys:
                try:
                    pubkey, keyidv2 = file_signatures.get_pubkey_from_file(key)
                    if not pubkey:
                        print(f"File '{key}' is not a file with a key")
                    else:
                        keyring.add_pubkey(pubkey, keyidv2)
                except ValueError as e:
                    print(f"File '{key}' does not have a supported key: {e}")
            verification_key_list = json.dumps(keyring.to_string())

    policy["excludes"] += excl_list
    if verification_key_list:
        policy["verification-keys"].append(verification_key_list)

    return policy


def main() -> None:

    parser = ConversionParser()
    parser.add_argument("-a", "--allowlist", help="allowlist file location", action="store")
    parser.add_argument("-i", "--ima_policy", help="IMA policy file location", action="store")
    parser.add_argument("-e", "--excludelist", help="exclude list file location", action="store")
    parser.add_argument("-v", "--verification_keys", help="list of verification key paths", nargs="+", default=[])
    parser.add_argument("-o", "--output_file", help="Output file path", action="store")

    # print help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()
    if bool(args.allowlist) and bool(args.ima_policy):
        print("Cannot provide both --allowlist and --ima-policy!")
        sys.exit(1)
    elif not bool(args.allowlist) and not bool(args.ima_policy):
        print("Either --allowlist or --ima_policy is required!")
        sys.exit(1)
    elif not args.output_file:
        print("An output file path (-o, --output_file) is required to write new policy!")
        sys.exit(1)

    if args.allowlist:
        policy = convert_legacy_allowlist(args.allowlist)
    elif args.ima_policy:
        with open(args.ima_policy, "r", encoding="utf8") as f:
            policy = json.load(f)
        if not isinstance(policy, Dict):
            print(f"The policy in file {args.ima_policy} must be a dictionary")
            sys.exit(1)
    else:
        assert False  # This cannot happen

    policy_out = update_ima_policy(policy, excludelist_path=args.excludelist, verification_keys=args.verification_keys)
    with open(args.output_file, "wb") as f:
        f.write(json.dumps(policy_out).encode())


class ConversionParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        sys.stderr.write(f"error: {message}\n")
        self.print_help(sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
