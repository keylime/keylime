'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import ast
import codecs
import hashlib
import struct
import os
import re
import json
import datetime
import functools

from keylime import config
from keylime import gpg
from keylime import keylime_logging
from keylime import ima_ast


logger = keylime_logging.init_logging('ima')


# The version of the allowlist format that is supported by this keylime release
ALLOWLIST_CURRENT_VERSION = 1


def read_unpack(fd, fmt):
    return struct.unpack(fmt, fd.read(struct.calcsize(fmt)))


def _validate_ima_ng(exclude_regex, allowlist, digest: ima_ast.Digest, path: ima_ast.Name):
    if allowlist is not None:
        if exclude_regex is not None and exclude_regex.match(path.name):
            logger.debug("IMA: ignoring excluded path %s" % path)
            return True

        accept_list = allowlist.get(path.name, None)
        if accept_list is None:
            logger.warning("File not found in allowlist: %s" % (path.name))
            return False

        if codecs.encode(digest.hash, 'hex').decode('utf-8') not in accept_list:
            logger.warning("Hashes for file %s don't match %s not in %s" %
                           (path.name,
                            codecs.encode(digest.hash, 'hex').decode('utf-8'),
                            accept_list))
            return False

    return True


def _validate_ima_sig(exclude_regex, ima_keyring, allowlist, digest: ima_ast.Digest, path: ima_ast.Name,
                      signature: ima_ast.Signature):
    valid_signature = False
    if ima_keyring and signature:

        if exclude_regex is not None and exclude_regex.match(path.name):
            logger.debug(f"IMA: ignoring excluded path {path.name}")
            return True

        if not ima_keyring.integrity_digsig_verify(signature.data, digest.hash, digest.algorithm):
            logger.warning(f"signature for file {path.name} is not valid")
            return False

        valid_signature = True
        logger.debug("signature for file %s is good" % path)

    # If there is also an allowlist verify the file against that but only do this if:
    # - we did not evaluate the signature (valid_siganture = False)
    # - the signature is valid and the file is also in the allowlist
    if allowlist is not None and \
        ((allowlist.get(path.name, None) is not None and valid_signature) or not valid_signature):
        # We use the normal ima_ng validator to validate hash
        return _validate_ima_ng(exclude_regex, allowlist, digest, path)

    # If we don't have a allowlist and don't have a keyring we just ignore the validation.
    if ima_keyring is None:
        return True

    return valid_signature


def process_measurement_list(lines, lists=None, m2w=None, pcrval=None, ima_keyring=None):
    running_hash = ima_ast.START_HASH
    found_pcr = (pcrval is None)
    errors = {}
    pcrval_bytes = b''
    if pcrval is not None:
        pcrval_bytes = codecs.decode(pcrval.encode('utf-8'), 'hex')

    if lists is not None:
        if isinstance(lists, str):
            lists = ast.literal_eval(lists)
        allow_list = lists['allowlist']
        exclude_list = lists['exclude']
    else:
        allow_list = None
        exclude_list = None

    is_valid, compiled_regex, err_msg = config.valid_exclude_list(exclude_list)
    if not is_valid:
        # This should not happen as the exclude list has already been validated
        # by the verifier before acceping it. This is a safety net just in case.
        err_msg += " Exclude list will be ignored."
        logger.error(err_msg)

    ima_validator = ima_ast.Validator(
        {ima_ast.ImaSig: functools.partial(_validate_ima_sig, compiled_regex, ima_keyring, allow_list),
         ima_ast.ImaNg: functools.partial(_validate_ima_ng, compiled_regex, allow_list),
         ima_ast.Ima: functools.partial(_validate_ima_ng, compiled_regex, allow_list)
         }
    )

    for line in lines:
        line = line.strip()
        if line == '':
            continue

        try:
            entry = ima_ast.Entry(line, ima_validator)

            # update hash
            running_hash = hashlib.sha1(running_hash + entry.template_hash).digest()

            if not entry.valid():
                errors[type(entry.mode)] = errors.get(type(entry.mode), 0) + 1

            if not found_pcr:
                # End of list should equal pcr value
                found_pcr = (running_hash == pcrval_bytes)

            # Keep old functionality for writing the parsed files with hashes into a file
            if m2w is not None and (type(entry.mode) in [ima_ast.Ima, ima_ast.ImaNg, ima_ast.ImaSig]):
                hash_value = codecs.encode(entry.mode.digest.hash, "hex")
                path = entry.mode.path.name
                m2w.write(f"{hash_value} {path}\n")
        except ima_ast.ParserError:
            logger.error(f"Line was not parsable into a valid IMA entry: {line}")

    # check PCR value has been found
    if not found_pcr:
        logger.error("IMA measurement list does not match TPM PCR %s" % pcrval)
        return None

    # Check if any validators failed
    if sum(errors.values()) > 0:
        error_msg = "IMA ERRORS: Some entries couldn't be validated. Number of failures in modes: "
        error_msg += ", ".join([f'{k.__name__ } {v}' for k, v in errors.items()])
        logger.error(error_msg + ".")
        return None

    return codecs.encode(running_hash, 'hex').decode('utf-8')


def process_allowlists(allowlist, exclude):
    # Pull in default config values if not specified
    if allowlist is None:
        allowlist = read_allowlist()
    if exclude is None:
        exclude = read_excllist()

    if allowlist['hashes'].get('boot_aggregate') is None:
        logger.warning("No boot_aggregate value found in allowlist, adding an empty one")
        allowlist['hashes']['boot_aggregate'] = ['0000000000000000000000000000000000000000']

    for excl in exclude:
        # remove commented out lines
        if excl.startswith("#"):
            exclude.remove(excl)
        # don't allow empty lines in exclude list, it will match everything
        if excl == "":
            exclude.remove(excl)

    return{'allowlist': allowlist['hashes'], 'exclude': exclude}


def read_allowlist(al_path=None, checksum="", gpg_sig_file=None, gpg_key_file=None):
    alist = {}
    if al_path is None:
        al_path = config.get('tenant', 'ima_allowlist')
        if config.STUB_IMA:
            al_path = '../scripts/ima/allowlist.txt'

    # If user only wants signatures then an allowlist is not required
    if al_path is None or al_path == '':
        return []

    # Purposefully die if path doesn't exist
    with open(al_path, 'r') as f:
        alist = f.read()
    alist = alist.splitlines()

    # verify GPG signature if needed
    if gpg_sig_file and gpg_key_file:
        gpg.gpg_verify_filesignature(gpg_key_file, al_path, gpg_sig_file, "allowlist")

    # Purposefully die if path doesn't exist
    with open(al_path, 'rb') as f:
        logger.debug("Loading allowlist from %s", al_path)
        alist_bytes = f.read()
        sha256 = hashlib.sha256()
        sha256.update(alist_bytes)
        calculated_checksum = sha256.hexdigest()
        alist_raw = alist_bytes.decode("utf-8")
        logger.debug("Loaded allowlist from %s with checksum %s", al_path, calculated_checksum)

    if checksum:
        if checksum == calculated_checksum:
            logger.debug("Allowlist passed checksum validation")
        else:
            raise Exception(f"Checksum of allowlist does not match! Expected {checksum}, Calculated {calculated_checksum}")

    # if the first non-whitespace character in the file is '{' treat it as the new JSON format
    p = re.compile(r'^\s*{')
    if p.match(alist_raw):
        logger.debug("Reading allow list as JSON format")
        alist = json.loads(alist_raw)

        # verify it's the current version
        if "meta" in alist and "version" in alist["meta"]:
            version = alist["meta"]["version"]
            if int(version) == ALLOWLIST_CURRENT_VERSION:
                logger.debug("Allowlist has compatible version %s", version)
            else:
                # in the future we will support multiple versions and convert between them,
                # but for now there is only one
                raise Exception("Allowlist has unsupported version {version}")
        else:
            logger.debug("Allowlist does not specify a version. Assuming current version %s", ALLOWLIST_CURRENT_VERSION)
    else:
        # convert legacy format into new structured format
        logger.debug("Converting legacy allowlist format to JSON")
        alist = {
            "meta": {
                "version": ALLOWLIST_CURRENT_VERSION,
                "generator": "keylime-legacy-format-upgrade",
                "timestamp": str(datetime.datetime.now()),
            },
            "release": 0,
            "hashes": {}
        }
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
            if path in alist["hashes"]:
                alist["hashes"][path].append(checksum_hash)
            else:
                alist["hashes"][path] = [checksum_hash]

    return alist


def read_excllist(exclude_path=None):
    if exclude_path is None:
        exclude_path = config.get('tenant', 'ima_excludelist')
        if config.STUB_IMA:
            exclude_path = '../scripts/ima/exclude.txt'

    excl_list = []
    if os.path.exists(exclude_path):
        with open(exclude_path, 'r') as f:
            excl_list = f.read()
        excl_list = excl_list.splitlines()

        logger.debug("Loaded exclusion list from %s: %s" %
                     (exclude_path, excl_list))

    return excl_list


def main():
    allowlist_path = 'allowlist.txt'
    print("reading allowlist from %s" % allowlist_path)

    exclude_path = 'exclude.txt'
    # exclude_path = '../scripts/ima/exclude.txt'
    print("reading exclude list from %s" % exclude_path)

    al_data = read_allowlist(allowlist_path)
    excl_data = read_excllist(exclude_path)
    lists = process_allowlists(al_data, excl_data)

    measure_path = config.IMA_ML
    # measure_path='../scripts/ima/ascii_runtime_measurements_ima'
    # measure_path = '../scripts/gerardo/ascii_runtime_measurements'
    print("reading measurement list from %s" % measure_path)
    f = open(measure_path, 'r')
    lines = f.readlines()

    m2a = open('measure2allow.txt', "w")
    digest = process_measurement_list(lines, lists, m2a)
    print("final digest is %s" % digest)
    f.close()
    m2a.close()

    print("using m2a")

    al_data = read_allowlist('measure2allow.txt')
    excl_data = read_excllist(exclude_path)
    lists2 = process_allowlists(al_data, excl_data)
    process_measurement_list(lines, lists2)

    print("done")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
