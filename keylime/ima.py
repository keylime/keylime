'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import codecs
import copy
import hashlib
import struct
import os
import re
import json
import datetime
import functools

from keylime import config
from keylime import gpg
from keylime import ima_ast
from keylime import ima_file_signatures
from keylime import keylime_logging
from keylime.agentstates import AgentAttestState
from keylime.common import algorithms, validators
from keylime.failure import Failure, Component


logger = keylime_logging.init_logging('ima')


# The version of the allowlist format that is supported by this keylime release
ALLOWLIST_CURRENT_VERSION = 5


class IMAMeasurementList:
    """ IMAMeasurementList models the IMA measurement lists's last known
        two numbers of entries and filesizes
    """
    instance = None

    @staticmethod
    def get_instance():
        """ Return a singleton """
        if not IMAMeasurementList.instance:
            IMAMeasurementList.instance = IMAMeasurementList()
        return IMAMeasurementList.instance

    def __init__(self):
        """ Constructor """
        self.entries = set()
        self.reset()

    def reset(self):
        """ Reset the variables """
        self.entries = set()

    def update(self, num_entries, filesize):
        """ Update the number of entries and current filesize of the log. """
        if len(self.entries) > 256:
            for entry in self.entries:
                self.entries.discard(entry)
                break
        self.entries.add((num_entries, filesize))

    def find(self, nth_entry):
        """ Find the closest entry to the n-th entry and return its number
            and filesize to seek to, return 0, 0 if nothing was found.
        """
        best = (0, 0)
        for entry in self.entries:
            if entry[0] > best[0] and entry[0] <= nth_entry:
                best = entry
        return best


def read_measurement_list(filename, nth_entry):
    """ Read the IMA measurement list starting from a given entry.
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

    if not os.path.exists(filename):
        IMAML.reset()
        nth_entry = 0
        logger.warning("IMA measurement list not available: %s", filename)
    else:
        with open(filename, 'r', encoding="utf-8") as f:
            f.seek(filesize)
            filedata = f.read()
        # filedata now corresponds to starting list at entry number 'IMAML.num_entries'
        # find n-th entry and determine number of total entries in file now
        offset = 0
        while True:
            try:
                if nth_entry == num_entries:
                    ml = filedata[offset:]
                o = filedata.index('\n', offset)
                offset = o + 1
                num_entries += 1
            except ValueError:
                break
        # IMAML.filesize corresponds to position for entry number 'IMAML.num_entries'
        IMAML.update(num_entries, filesize + offset)

        # Nothing found? User request beyond next-expected entry.
        # Start over with entry 0. This cannot recurse again.
        if ml is None:
            return read_measurement_list(filename, 0)

    return ml, nth_entry, num_entries


def read_unpack(fd, fmt):
    return struct.unpack(fmt, fd.read(struct.calcsize(fmt)))



def _validate_ima_ng(exclude_regex, allowlist, digest: ima_ast.Digest, path: ima_ast.Name, hash_types='hashes') -> Failure:
    failure = Failure(Component.IMA, ["validation", "ima-ng"])
    if allowlist is not None:
        if exclude_regex is not None and exclude_regex.match(path.name):
            logger.debug("IMA: ignoring excluded path %s" % path)
            return failure

        accept_list = allowlist[hash_types].get(path.name, None)
        if accept_list is None:
            logger.warning(f"File not found in allowlist: {path.name}")
            failure.add_event("not_in_allowlist", f"File not found in allowlist: {path.name}", True)
            return failure

        if codecs.encode(digest.hash, 'hex').decode('utf-8') not in accept_list:
            logger.warning("Hashes for file %s don't match %s not in %s" %
                           (path.name,
                            codecs.encode(digest.hash, 'hex').decode('utf-8'),
                            accept_list))
            failure.add_event(
                "allowlist_hash",
                {"message": "Hash not in allowlist found",
                 "got": codecs.encode(digest.hash, 'hex').decode('utf-8'),
                 "expected": accept_list}, True)
            return failure

    return failure


def _validate_ima_sig(exclude_regex, ima_keyrings, allowlist, digest: ima_ast.Digest, path: ima_ast.Name,
                      signature: ima_ast.Signature) -> Failure:
    failure = Failure(Component.IMA, ["validator", "ima-sig"])
    valid_signature = False
    if ima_keyrings and signature:

        if exclude_regex is not None and exclude_regex.match(path.name):
            logger.debug(f"IMA: ignoring excluded path {path.name}")
            return failure

        if not ima_keyrings.integrity_digsig_verify(signature.data, digest.hash, digest.algorithm):
            logger.warning(f"signature for file {path.name} is not valid")
            failure.add_event("invalid_signature", f"signature for file {path.name} is not valid", True)
            return failure

        valid_signature = True
        logger.debug("signature for file %s is good" % path)

    # If there is also an allowlist verify the file against that but only do this if:
    # - we did not evaluate the signature (valid_siganture = False)
    # - the signature is valid and the file is also in the allowlist
    if allowlist is not None and allowlist.get('hashes') is not None and \
        ((allowlist['hashes'].get(path.name, None) is not None and valid_signature) or not valid_signature):
        # We use the normal ima_ng validator to validate hash
        return _validate_ima_ng(exclude_regex, allowlist, digest, path)

    # If we don't have a allowlist and don't have a keyring we just ignore the validation.
    if ima_keyrings is None:
        return failure

    if not valid_signature:
        failure.add_event("invalid_signature", f"signature for file {path.name} could not be validated", True)
    return failure


def _validate_ima_buf(exclude_regex, allowlist, ima_keyrings: ima_file_signatures.ImaKeyrings, digest: ima_ast.Digest, path: ima_ast.Name, data: ima_ast.Buffer):
    failure = Failure(Component.IMA)
    # Is data.data a key?
    pubkey, keyidv2 = ima_file_signatures.get_pubkey(data.data)
    if pubkey:
        ignored_keyrings = allowlist['ima']['ignored_keyrings']
        if '*' not in ignored_keyrings and path.name not in ignored_keyrings:
            failure = _validate_ima_ng(exclude_regex, allowlist, digest, path, hash_types='keyrings')
            if not failure:
                # Add the key only now that it's validated (no failure)
                ima_keyrings.add_pubkey_to_keyring(pubkey, path.name, keyidv2=keyidv2)
    else:
        # handling of generic ima-buf entries that for example carry a hash in the buf field
        failure = _validate_ima_ng(exclude_regex, allowlist, digest, path, hash_types='ima-buf')

    # Anything else evaluates to true for now
    return failure


def _process_measurement_list(agentAttestState, lines, hash_alg, lists=None, m2w=None, pcrval=None, ima_keyrings=None,
                              boot_aggregates=None):
    failure = Failure(Component.IMA)
    running_hash = agentAttestState.get_pcr_state(config.IMA_PCR, hash_alg)
    found_pcr = (pcrval is None)
    errors = {}
    pcrval_bytes = b''
    if pcrval is not None:
        pcrval_bytes = codecs.decode(pcrval.encode('utf-8'), 'hex')

    if lists is not None:
        if isinstance(lists, str):
            lists = json.loads(lists)
        allow_list = lists['allowlist']
        exclude_list = lists['exclude']
    else:
        allow_list = None
        exclude_list = None

    ima_log_hash_alg = algorithms.Hash.SHA1
    if allow_list is not None:
        try:
            ima_log_hash_alg = algorithms.Hash(allow_list["ima"]["log_hash_alg"])
        except ValueError:
            logger.warning("Specified IMA log hash algorithm %s is not a valid algorithm! Defaulting to SHA1.",
                           allow_list["ima"]["log_hash_alg"])

    if boot_aggregates and allow_list:
        if 'boot_aggregate' not in allow_list['hashes'] :
            allow_list['hashes']['boot_aggregate'] = []
        for alg in boot_aggregates.keys() :
            for val in boot_aggregates[alg] :
                if val not in allow_list['hashes']['boot_aggregate'] :
                    allow_list['hashes']['boot_aggregate'].append(val)

    is_valid, compiled_regex, err_msg = validators.valid_exclude_list(exclude_list)
    if not is_valid:
        # This should not happen as the exclude list has already been validated
        # by the verifier before acceping it. This is a safety net just in case.
        err_msg += " Exclude list will be ignored."
        logger.error(err_msg)

    ima_validator = ima_ast.Validator(
        {ima_ast.ImaSig: functools.partial(_validate_ima_sig, compiled_regex, ima_keyrings, allow_list),
         ima_ast.ImaNg: functools.partial(_validate_ima_ng, compiled_regex, allow_list),
         ima_ast.Ima: functools.partial(_validate_ima_ng, compiled_regex, allow_list),
         ima_ast.ImaBuf: functools.partial(_validate_ima_buf, compiled_regex, allow_list, ima_keyrings),
         }
    )

    # Iterative attestation may send us no log [len(lines) == 1]; compare last know PCR 10 state
    # against current PCR state.
    # Since IMA log append and PCR extend is not atomic, we may get a quote that does not yet take
    # into account the next appended measurement's [len(lines) == 2] PCR extension.
    if not found_pcr and len(lines) <= 2:
        found_pcr = (running_hash == pcrval_bytes)

    for linenum, line in enumerate(lines):
        line = line.strip()
        if line == '':
            continue

        try:
            entry = ima_ast.Entry(line, ima_validator, ima_hash_alg=ima_log_hash_alg, pcr_hash_alg=hash_alg)

            # update hash
            running_hash = hash_alg.hash(running_hash + entry.pcr_template_hash)

            validation_failure = entry.invalid()

            if validation_failure:
                failure.merge(validation_failure)
                errors[type(entry.mode)] = errors.get(type(entry.mode), 0) + 1

            if not found_pcr:
                # End of list should equal pcr value
                found_pcr = (running_hash == pcrval_bytes)
                if found_pcr:
                    logger.debug('Found match at linenum %s' % (linenum + 1))
                    # We always want to have the very last line for the attestation, so
                    # we keep the previous runninghash, which is not the last one!
                    agentAttestState.update_ima_attestation(int(entry.pcr), running_hash, linenum + 1)

            # Keep old functionality for writing the parsed files with hashes into a file
            if m2w is not None and (type(entry.mode) in [ima_ast.Ima, ima_ast.ImaNg, ima_ast.ImaSig]):
                hash_value = codecs.encode(entry.mode.digest.bytes, "hex")
                path = entry.mode.path.name
                m2w.write(f"{hash_value} {path}\n")
        except ima_ast.ParserError:
            failure.add_event("entry", f"Line was not parsable into a valid IMA entry: {line}", True, ["parser"])
            logger.error(f"Line was not parsable into a valid IMA entry: {line}")

    # check PCR value has been found
    if not found_pcr:
        logger.error(f"IMA measurement list does not match TPM PCR {pcrval}")
        failure.add_event("pcr_mismatch", f"IMA measurement list does not match TPM PCR {pcrval}", True)

    # Check if any validators failed
    if sum(errors.values()) > 0:
        error_msg = "IMA ERRORS: Some entries couldn't be validated. Number of failures in modes: "
        error_msg += ", ".join([f'{k.__name__ } {v}' for k, v in errors.items()])
        logger.error(error_msg + ".")

    return codecs.encode(running_hash, 'hex').decode('utf-8'), failure


def process_measurement_list(agentAttestState, lines, lists=None, m2w=None, pcrval=None, ima_keyrings=None,
                             boot_aggregates=None, hash_alg=algorithms.Hash.SHA1):
    failure = Failure(Component.IMA)
    try:
        running_hash, failure = _process_measurement_list(agentAttestState, lines, hash_alg, lists=lists, m2w=m2w,
                                                          pcrval=pcrval, ima_keyrings=ima_keyrings,
                                                          boot_aggregates=boot_aggregates)
    except:  # pylint: disable=try-except-raise
        raise
    finally:
        if failure:
            # TODO currently reset on any failure which might be an issue
            agentAttestState.reset_ima_attestation()

    return running_hash, failure

def update_allowlist(allowlist):
    """ Update the allowlist to the latest version adding default values for missing fields """
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

    return allowlist

def process_allowlists(allowlist, exclude):
    # Pull in default config values if not specified
    if allowlist is None:
        allowlist = read_allowlist()
    else:
        allowlist = update_allowlist(allowlist)

    if exclude is None:
        exclude = read_excllist()

    if allowlist['hashes'].get('boot_aggregate') is None:
        logger.warning("No boot_aggregate value found in allowlist, adding an empty one")
        allowlist['hashes']['boot_aggregate'] = ['0'*40, '0'*64]

    for excl in exclude:
        # remove commented out lines
        if excl.startswith("#"):
            exclude.remove(excl)
        # don't allow empty lines in exclude list, it will match everything
        if excl == "":
            exclude.remove(excl)

    return{'allowlist': allowlist, 'exclude': exclude}

# IMA allowlists of versions older than 5 will not have the "log_hash_alg"
# parameter. Hard-coding it to "sha1" is perfectly fine, and the fact one
# specifies a different algorithm on the kernel command line (e.g., ima_hash=sha256)
# does not affect normal operation of Keylime, since it does not validate the
# hash algorithm received from agent's IMA runtime measurements.
# The only situation where this hard-coding would become a problem is if and when
# the kernel maintainers decide to use a different algorithm for template-hash.
empty_allowlist = {
    "meta": {
        "version": ALLOWLIST_CURRENT_VERSION,
        },
    "release": 0,
    "hashes": {},
    "keyrings": {},
    "ima": {
        "ignored_keyrings": [],
        "log_hash_alg": "sha1"
    }
}

def read_allowlist(al_path=None, checksum="", gpg_sig_file=None, gpg_key_file=None):
    if al_path is None:
        al_path = config.get('tenant', 'ima_allowlist')
        if config.STUB_IMA:
            al_path = '../scripts/ima/allowlist.txt'

    # If user only wants signatures then an allowlist is not required
    if al_path is None or al_path == '':
        return copy.deepcopy(empty_allowlist)

    # Purposefully die if path doesn't exist
    with open(al_path, 'rb') as f:
        pass

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
            if int(version) <= ALLOWLIST_CURRENT_VERSION:
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

        alist = copy.deepcopy(empty_allowlist)
        alist["meta"]["timestamp"] = str(datetime.datetime.now())
        alist["meta"]["generator"] = "keylime-legacy-format-upgrade"
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
                path = path[len("%keyring:"):]  # remove leading '%keyring:' from path to get keyring name
            else:
                entrytype = "hashes"

            if path in alist[entrytype]:
                alist[entrytype][path].append(checksum_hash)
            else:
                alist[entrytype][path] = [checksum_hash]

    alist = update_allowlist(alist)

    return alist


def read_excllist(exclude_path=None):
    if exclude_path is None:
        exclude_path = config.get('tenant', 'ima_excludelist')
        if config.STUB_IMA:
            exclude_path = '../scripts/ima/exclude.txt'

    excl_list = []
    if os.path.exists(exclude_path):
        with open(exclude_path, encoding="utf-8") as f:
            for line in f :
                line = line.strip()
                if line.startswith('#') or len(line) == 0:
                    continue
                excl_list.append(line)

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
    f = open(measure_path, encoding="ascii")
    lines = f.readlines()

    m2a = open('measure2allow.txt', "w", encoding="utf-8")
    digest = process_measurement_list(AgentAttestState('1'), lines, lists, m2a)
    print("final digest is %s" % digest)
    f.close()
    m2a.close()

    print("using m2a")

    al_data = read_allowlist('measure2allow.txt')
    excl_data = read_excllist(exclude_path)
    lists2 = process_allowlists(al_data, excl_data)
    process_measurement_list(AgentAttestState('2'), lines, lists2)

    print("done")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
