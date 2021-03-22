'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

from abc import ABCMeta, abstractmethod
import ast
import fcntl
import hashlib
import os
import string
import struct

import simplejson as json
import yaml
try:
    from yaml import CSafeLoader as SafeLoader, CSafeDumper as SafeDumper
except ImportError:
    from yaml import SafeLoader, SafeDumper

from keylime import config
from keylime import keylime_logging
from keylime import crypto
from keylime import ima
from keylime.common import algorithms
from keylime.elchecking import policies as eventlog_policies

logger = keylime_logging.init_logging('tpm')


class TPM_Utilities:

    @staticmethod
    def check_mask(mask, pcr):
        if mask is None:
            return False
        return bool(1 << pcr & int(mask, 0))

    @staticmethod
    def random_password(length=20):
        rand = crypto.generate_random_key(length)
        chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
        password = ''
        for i in range(length):
            password += chars[(rand[i]) % len(chars)]
        return password

    @staticmethod
    def readPolicy(configval):
        policy = json.loads(configval)

        # compute PCR mask from tpm_policy
        mask = 0
        for key in list(policy.keys()):
            if not key.isdigit() or int(key) > 24:
                raise Exception("Invalid tpm policy pcr number: %s" % (key))

            if int(key) == config.TPM_DATA_PCR:
                raise Exception("Invalid allowlist PCR number %s, keylime uses this PCR to bind data." % key)
            if int(key) == config.IMA_PCR:
                raise Exception("Invalid allowlist PCR number %s, this PCR is used for IMA." % key)

            mask = mask + (1 << int(key))

            # wrap it in a list if it is a singleton
            if isinstance(policy[key], str):
                policy[key] = [policy[key]]

            # convert all hash values to lowercase
            policy[key] = [x.lower() for x in policy[key]]

        policy['mask'] = "0x%X" % (mask)
        return policy


class AbstractTPM(metaclass=ABCMeta):
    # Abstract base class
    EXIT_SUCESS = 0
    TPM_IO_ERR = 5
    EMPTYMASK = "1"

    # constructor
    def __init__(self, need_hw_tpm=True):
        # read the config file
        self.need_hw_tpm = need_hw_tpm
        self.global_tpmdata = None
        self.tpmrand_warned = False
        self.defaults = {}
        self.defaults['hash'] = algorithms.Hash.SHA1
        self.defaults['encrypt'] = algorithms.Encrypt.RSA
        self.defaults['sign'] = algorithms.Sign.RSASSA
        self.supported = {}

    # tpm_initialize
    @abstractmethod
    def flush_keys(self):
        pass

    @abstractmethod
    def encryptAIK(self, uuid, ek_tpm: bytes, aik_tpm: bytes):
        pass

    @abstractmethod
    def activate_identity(self, keyblob):
        pass

    @abstractmethod
    def verify_ek(self, ekcert):
        pass

    @abstractmethod
    def get_tpm_manufacturer(self):
        pass

    @abstractmethod
    def is_emulator(self):
        pass

    @abstractmethod
    def is_vtpm(self):
        pass

    def warn_emulator(self):
        if self.is_emulator():
            logger.warning("INSECURE: Keylime is using a software TPM emulator rather than a real hardware TPM.")
            logger.warning("INSECURE: The security of Keylime is NOT linked to a hardware root of trust.")
            logger.warning("INSECURE: Only use Keylime in this mode for testing or debugging purposes.")

    def __read_tpm_data(self):
        if os.path.exists('tpmdata.yml'):
            with open('tpmdata.yml', 'rb') as f:
                return yaml.load(f, Loader=SafeLoader)
        else:
            return {}

    def __write_tpm_data(self):
        os.umask(0o077)
        if os.geteuid() != 0 and config.REQUIRE_ROOT:
            logger.warning("Creating tpm metadata file without root. Sensitive trust roots may be at risk!")
        with open('tpmdata.yml', 'w') as f:
            yaml.dump(self.global_tpmdata, f, Dumper=SafeDumper)

    def get_tpm_metadata(self, key):
        if self.global_tpmdata is None:
            self.global_tpmdata = self.__read_tpm_data()
        return self.global_tpmdata.get(key, None)

    def _set_tpm_metadata(self, key, value):
        if self.global_tpmdata is None:
            self.global_tpmdata = self.__read_tpm_data()

        if self.global_tpmdata.get(key, None) is not value:
            self.global_tpmdata[key] = value
            self.__write_tpm_data()

    @abstractmethod
    def tpm_init(self, self_activate=False, config_pw=None):
        pass

    # tpm_quote
    @abstractmethod
    def create_quote(self, nonce, data=None, pcrmask=EMPTYMASK, hash_alg=None):
        pass

    @abstractmethod
    def check_quote(self, agent_id, nonce, data, quote, aikTpmFromRegistrar, tpm_policy={}, ima_measurement_list=None, allowlist={}, hash_alg=None, ima_keyring=None, mb_measurement_list=None, mb_refstate=None):
        pass

    def START_HASH(self, algorithm=None):
        if algorithm is None:
            algorithm = self.defaults['hash']

        alg_size = algorithms.get_hash_size(algorithm) // 4
        return "0" * alg_size

    def hashdigest(self, payload, algorithm=None):
        if algorithm is None:
            algorithm = self.defaults['hash']

        if algorithm == algorithms.Hash.SHA1:
            measured = hashlib.sha1(payload).hexdigest()
        elif algorithm == algorithms.Hash.SHA256:
            measured = hashlib.sha256(payload).hexdigest()
        elif algorithm == algorithms.Hash.SHA384:
            measured = hashlib.sha384(payload).hexdigest()
        elif algorithm == algorithms.Hash.SHA512:
            measured = hashlib.sha512(payload).hexdigest()
        else:
            measured = None
        return measured

    @abstractmethod
    def sim_extend(self, hashval_1, hashval_0=None):
        pass

    @abstractmethod
    def extendPCR(self, pcrval, hashval, hash_alg=None, lock=True):
        pass

    @abstractmethod
    def readPCR(self, pcrval, hash_alg=None):
        pass

    @abstractmethod
    def _get_tpm_rand_block(self, size=4096):
        pass

    def __check_ima(self, agent_id, pcrval, ima_measurement_list, allowlist, ima_keyring):
        logger.info("Checking IMA measurement list on agent: %s", agent_id)
        if config.STUB_IMA:
            pcrval = None
        ex_value = ima.process_measurement_list(ima_measurement_list.split('\n'), allowlist, pcrval=pcrval, ima_keyring=ima_keyring)
        if ex_value is None:
            return False

        logger.debug("IMA measurement list of agent %s validated", agent_id)
        return True

    def check_pcrs(self, agent_id, tpm_policy, pcrs, data, virtual, ima_measurement_list, allowlist, ima_keyring, mb_measurement_list, mb_refstate_str):
        try:
            tpm_policy_ = ast.literal_eval(tpm_policy)
        except ValueError:
            tpm_policy_ = {}
        pcr_allowlist = tpm_policy_.copy()

        if mb_refstate_str:
            mb_refstate_data = json.loads(mb_refstate_str)
        else:
            mb_refstate_data = None

        if 'mask' in pcr_allowlist:
            del pcr_allowlist['mask']
        # convert all pcr num keys to integers
        pcr_allowlist = {int(k): v for k, v in list(pcr_allowlist.items())}

        if mb_refstate_data :
            mb_policy_name = config.MEASUREDBOOT_POLICYNAME
            mb_policy = eventlog_policies.get_policy(mb_policy_name)
            if mb_policy is None:
                logger.warning(
                    "Invalid measured boot policy name %s -- using accept-all instead.", mb_policy_name)
                mb_policy = eventlog_policies.AcceptAll()

            mb_pcrs_config = frozenset(config.MEASUREDBOOT_PCRS)
            mb_pcrs_policy = mb_policy.get_relevant_pcrs()
            if not mb_pcrs_policy <= mb_pcrs_config:
                logger.error("Measured boot policy considers PCRs %s, which are not among the configured set %s",
                            set(mb_pcrs_policy - mb_pcrs_config), set(mb_pcrs_config))

        if mb_refstate_data and mb_measurement_list :
            mb_measurement_data = self.parse_bootlog(mb_measurement_list)
            if not mb_measurement_data :
                logger.error("Unable to parse measured boot event log. Check previous messages for a reason for error.")
                return False
            log_pcrs = mb_measurement_data.get('pcrs')
            if not isinstance(log_pcrs, dict):
                logger.error("Parse of measured boot event log has unexpected value for .pcrs: %r", log_pcrs)
                return False
            pcrs_sha256 = log_pcrs.get('sha256')
            if (not isinstance(pcrs_sha256, dict)) or not pcrs_sha256:
                logger.error("Parse of measured boot event log has unexpected value for .pcrs.sha256: %r", pcrs_sha256)
                return False
        else:
            pcrs_sha256 = {}

        pcrsInQuote = set()
        validatedBindPCR = False
        for line in pcrs:
            tokens = line.split()
            if len(tokens) < 3:
                logger.error("Invalid %sPCR in quote: %s", ("", "v")[virtual], pcrs)
                continue

            # always lower case
            pcrval = tokens[2].lower()
            # convert pcr num to number
            try:
                pcrnum = int(tokens[1])
            except Exception:
                logger.error("Invalid PCR number %s", tokens[1])

            if pcrnum == config.TPM_DATA_PCR and data is not None:
                expectedval = self.sim_extend(data)
                if expectedval != pcrval and not config.STUB_TPM:
                    logger.error("%sPCR #%s: invalid bind data %s from quote does not match expected value %s", ("", "v")[virtual], pcrnum, pcrval, expectedval)
                    return False
                validatedBindPCR = True
                continue

            # check for ima PCR
            if pcrnum == config.IMA_PCR and not config.STUB_TPM:
                if ima_measurement_list is None:
                    logger.error("IMA PCR in policy, but no measurement list provided")
                    return False

                if self.__check_ima(agent_id, pcrval, ima_measurement_list, allowlist, ima_keyring):
                    pcrsInQuote.add(pcrnum)
                    continue

                return False

            # PCRs set by measured boot get their own special handling

            if pcrnum in config.MEASUREDBOOT_PCRS :

                if mb_refstate_data :

                    if not mb_measurement_list :
                        logger.error("Measured Boot PCR %d in policy, but no measurement list provided", pcrnum)
                        return False

                    val_from_log_int = pcrs_sha256.get(str(pcrnum), 0)
                    val_from_log_hex = hex(val_from_log_int)[2:]
                    val_from_log_hex_stripped = val_from_log_hex.lstrip('0')
                    pcrval_stripped = pcrval.lstrip('0')
                    if val_from_log_hex_stripped != pcrval_stripped:
                        logger.error("For PCR %d and hash SHA256 the boot event log has value %r but the agent returned %r", pcrnum, val_from_log_hex, pcrval)
                        return False
                pcrsInQuote.add(pcrnum)
                continue

            if pcrnum not in list(pcr_allowlist.keys()):
                if not config.STUB_TPM and len(list(tpm_policy.keys())) > 0:
                    logger.warning("%sPCR #%s in quote not found in %stpm_policy, skipping.", ("", "v")[virtual], pcrnum, ("", "v")[virtual])
                continue
            if pcrval not in pcr_allowlist[pcrnum] and not config.STUB_TPM:
                logger.error("%sPCR #%s: %s from quote does not match expected value %s", ("", "v")[virtual], pcrnum, pcrval, pcr_allowlist[pcrnum])
                return False

            pcrsInQuote.add(pcrnum)

        if config.STUB_TPM:
            return True

        if not validatedBindPCR:
            logger.error("Binding %sPCR #%s was not included in the quote, but is required", ("", "v")[virtual], config.TPM_DATA_PCR)
            return False

        missing = list(set(list(pcr_allowlist.keys())).difference(pcrsInQuote))
        if len(missing) > 0:
            logger.error("%sPCRs specified in policy not in quote: %s", ("", "v")[virtual], missing)
            return False

        if mb_refstate_data :
            missing = list(set(config.MEASUREDBOOT_PCRS).difference(pcrsInQuote))
            if len(missing) > 0:
                logger.error("%sPCRs specified for measured boot not in quote: %s", ("", "v")[virtual], missing)
                return False
            try:
                reason = mb_policy.evaluate(mb_refstate_data, mb_measurement_data)
            except Exception as exn:
                logger.error("Boot attestation for agent %s, configured policy %s, refstate=%s, raised Exception %s",
                    agent_id, config.MEASUREDBOOT_POLICYNAME, json.dumps(mb_refstate_data), str(exn))
                reason = ''
            if reason:
                logger.error("Boot attestation failed for agent %s, configured policy %s, refstate=%s, reason=%s",
                    agent_id, config.MEASUREDBOOT_POLICYNAME, json.dumps(mb_refstate_data), reason)
                return False

        return True

    # tpm_random
    def init_system_rand(self):
        RNDADDENTROPY = 0x40085203
        rand_data = self._get_tpm_rand_block()
        if config.REQUIRE_ROOT and rand_data is not None:
            try:
                t = struct.pack("ii%ds" % len(rand_data), 8, len(rand_data), rand_data)
                with open("/dev/random", mode='wb') as fp:
                    # as fp has a method fileno(), you can pass it to ioctl
                    fcntl.ioctl(fp, RNDADDENTROPY, t)
            except Exception as e:
                logger.warning("TPM randomness not added to system entropy pool: %s", e)

    # tpm_nvram
    @abstractmethod
    def write_key_nvram(self, key):
        pass

    @abstractmethod
    def read_key_nvram(self):
        pass

    @abstractmethod
    def parse_bootlog(self, log_b64:str) -> dict:
        raise NotImplementedError
