'''DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''

import base64
import configparser
import fcntl
import hashlib
import os
import string
import struct
import yaml
import codecs
try:
    from yaml import CSafeLoader as SafeLoader, CSafeDumper as SafeDumper
except ImportError:
    from yaml import SafeLoader as SafeLoader, SafeDumper as SafeDumper

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

from abc import ABCMeta, abstractmethod

from keylime import common
from keylime import keylime_logging
from keylime import crypto
from keylime import ima

logger = keylime_logging.init_logging('tpm')


class Hash_Algorithms:
    SHA1 = 'sha1'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'

    @staticmethod
    def get_hash_size(algorithm):
        if algorithm == Hash_Algorithms.SHA1:
            return 160
        elif algorithm == Hash_Algorithms.SHA256:
            return 256
        elif algorithm == Hash_Algorithms.SHA384:
            return 384
        elif algorithm == Hash_Algorithms.SHA512:
            return 512
        else:
            return 0

    @staticmethod
    def is_accepted(algorithm, accepted):
        for alg in accepted:
            if alg == algorithm:
                return True
        return False

    @staticmethod
    def is_recognized(algorithm):
        if algorithm == Hash_Algorithms.SHA1:
            return True
        elif algorithm == Hash_Algorithms.SHA256:
            return True
        elif algorithm == Hash_Algorithms.SHA384:
            return True
        elif algorithm == Hash_Algorithms.SHA512:
            return True
        else:
            return False


class Encrypt_Algorithms:
    RSA = 'rsa'
    ECC = 'ecc'

    @staticmethod
    def is_accepted(algorithm, accepted):
        for alg in accepted:
            if alg == algorithm:
                return True
        return False

    @staticmethod
    def is_recognized(algorithm):
        if algorithm == Encrypt_Algorithms.RSA:
            return True
        elif algorithm == Encrypt_Algorithms.ECC:
            return True
        else:
            return False


class Sign_Algorithms:
    RSASSA = 'rsassa'
    RSAPSS = 'rsapss'
    ECDSA = 'ecdsa'
    ECDAA = 'ecdaa'
    ECSCHNORR = 'ecschnorr'

    @staticmethod
    def is_accepted(algorithm, accepted):
        for alg in accepted:
            if alg == algorithm:
                return True
        return False

    @staticmethod
    def is_recognized(algorithm):
        if algorithm == Sign_Algorithms.RSASSA:
            return True
        elif algorithm == Sign_Algorithms.RSAPSS:
            return True
        elif algorithm == Sign_Algorithms.ECDSA:
            return True
        elif algorithm == Sign_Algorithms.ECDAA:
            return True
        elif algorithm == Sign_Algorithms.ECSCHNORR:
            return True
        else:
            return False


class TPM_Utilities:

    @staticmethod
    def check_mask(mask, pcr):
        if mask is None:
            return False
        return bool(1<<pcr & int(mask, 0))

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
                raise Exception("Invalid tpm policy pcr number: %s"%(key))

            if int(key) == common.TPM_DATA_PCR:
                raise Exception("Invalid whitelist PCR number %s, keylime uses this PCR to bind data."%key)
            if int(key) == common.IMA_PCR:
                raise Exception("Invalid whitelist PCR number %s, this PCR is used for IMA."%key)

            mask = mask + (1<<int(key))

            # wrap it in a list if it is a singleton
            if isinstance(policy[key], str):
                policy[key] = [policy[key]]

            # convert all hash values to lowercase
            policy[key] = [x.lower() for x in policy[key]]

        policy['mask'] = "0x%X"%(mask)
        return policy


class AbstractTPM(object, metaclass=ABCMeta):
    # Abstract base class
    EXIT_SUCESS = 0
    TPM_IO_ERR = 5
    EMPTYMASK = "1"
    EMPTY_PCR = "0000000000000000000000000000000000000000"

    # constructor
    def __init__(self, need_hw_tpm=True):
        # read the config file
        self.config = configparser.RawConfigParser()
        self.config.read(common.CONFIG_FILE)
        self.need_hw_tpm = need_hw_tpm
        self.global_tpmdata = None
        self.tpmrand_warned = False
        self.defaults = {}
        self.defaults['hash'] = Hash_Algorithms.SHA1
        self.defaults['encrypt'] = Encrypt_Algorithms.RSA
        self.defaults['sign'] = Sign_Algorithms.RSASSA
        self.supported = {}

    @abstractmethod
    def get_tpm_version(self):
        pass

    # tpm_initialize
    @abstractmethod
    def flush_keys(self):
        pass

    @abstractmethod
    def encryptAIK(self, uuid, pubaik, pubek, ek_tpm, aik_name):
        pass

    @abstractmethod
    def activate_identity(self, keyblob):
        pass

    @abstractmethod
    def verify_ek(self, ekcert, ekpem):
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
        if os.geteuid() != 0 and common.REQUIRE_ROOT:
            logger.warning("Creating tpm metadata file without root.  Sensitive trust roots may be at risk!")
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


    #tpm_quote
    @abstractmethod
    def create_deep_quote(self, nonce, data=None, vpcrmask=EMPTYMASK, pcrmask=EMPTYMASK):
        pass

    @abstractmethod
    def create_quote(self, nonce, data=None, pcrmask=EMPTYMASK, hash_alg=None):
        pass

    def is_deep_quote(self, quote):
        if quote[0] == 'd':
            return True
        elif quote[0] == 'r':
            return False
        else:
            raise Exception("Invalid quote type %s"%quote[0])

    @abstractmethod
    def check_deep_quote(self, nonce, data, quote, vAIK, hAIK, vtpm_policy={}, tpm_policy={}, ima_measurement_list=None, ima_whitelist={}):
        pass

    @abstractmethod
    def check_quote(self, nonce, data, quote, aikFromRegistrar, tpm_policy={}, ima_measurement_list=None, ima_whitelist={}, hash_alg=None):
        pass

    def hashdigest(self, payload, algorithm=None):
        if algorithm is None:
            algorithm = self.defaults['hash']

        if algorithm == Hash_Algorithms.SHA1:
            measured = hashlib.sha1(payload).hexdigest()
        elif algorithm == Hash_Algorithms.SHA256:
            measured = hashlib.sha256(payload).hexdigest()
        elif algorithm == Hash_Algorithms.SHA384:
            measured = hashlib.sha384(payload).hexdigest()
        elif algorithm == Hash_Algorithms.SHA512:
            measured = hashlib.sha512(payload).hexdigest()
        else:
            measured = None
        return measured

    @abstractmethod
    def extendPCR(self, pcrval, hashval, hash_alg=None, lock=True):
        pass

    @abstractmethod
    def readPCR(self, pcrval, hash_alg=None):
        pass

    def __check_ima(self, pcrval, ima_measurement_list, ima_whitelist):
        logger.info("Checking IMA measurement list...")
        ex_value = ima.process_measurement_list(ima_measurement_list.split('\n'), ima_whitelist)
        if ex_value is None:
            return False

        if pcrval != ex_value and not common.STUB_IMA:
            logger.error("IMA measurement list expected pcr value %s does not match TPM PCR %s"%(ex_value, pcrval))
            return False
        logger.debug("IMA measurement list validated")
        return True

    def check_pcrs(self, tpm_policy, pcrs, data, virtual, ima_measurement_list, ima_whitelist):
        pcrWhiteList = tpm_policy.copy()
        if 'mask' in pcrWhiteList: del pcrWhiteList['mask']
        # convert all pcr num keys to integers
        pcrWhiteList = {int(k):v for k, v in list(pcrWhiteList.items())}

        pcrsInQuote = set()
        for line in pcrs:
            tokens = line.split()
            if len(tokens) < 3:
                logger.error("Invalid %sPCR in quote: %s"%(("", "v")[virtual], pcrs))
                continue

            # always lower case
            pcrval = tokens[2].lower()
            # convert pcr num to number
            try:
                pcrnum = int(tokens[1])
            except Exception:
                logger.error("Invalid PCR number %s"%tokens[1])

            if pcrnum == common.TPM_DATA_PCR and data is not None:
                # compute expected value  H(0|H(string(H(data))))
                # confused yet?  pcrextend will hash the string of the original hash again
                expectedval = hashlib.sha1(codecs.decode(AbstractTPM.EMPTY_PCR,'hex_codec')+hashlib.sha1(hashlib.sha1(data.encode('utf-8')).hexdigest().encode('utf-8')).digest()).hexdigest().lower()
                if expectedval != pcrval and not common.STUB_TPM:
                    logger.error("%sPCR #%s: invalid bind data %s from quote does not match expected value %s"%(("", "v")[virtual], pcrnum, pcrval, expectedval))
                    return False
                continue

            # check for ima PCR
            if pcrnum == common.IMA_PCR and not common.STUB_TPM:
                if ima_measurement_list is None:
                    logger.error("IMA PCR in policy, but no measurement list provided")
                    return False

                if self.__check_ima(pcrval, ima_measurement_list, ima_whitelist):
                    pcrsInQuote.add(pcrnum)
                    continue
                else:
                    return False

            if pcrnum not in list(pcrWhiteList.keys()):
                if not common.STUB_TPM and len(list(tpm_policy.keys())) > 0:
                    logger.warn("%sPCR #%s in quote not found in %stpm_policy, skipping."%(("", "v")[virtual], pcrnum, ("", "v")[virtual]))
                continue
            elif pcrval not in pcrWhiteList[pcrnum] and not common.STUB_TPM:
                logger.error("%sPCR #%s: %s from quote does not match expected value %s"%(("", "v")[virtual], pcrnum, pcrval, pcrWhiteList[pcrnum]))
                return False
            else:
                pcrsInQuote.add(pcrnum)

        if common.STUB_TPM:
            return True

        missing = list(set(list(pcrWhiteList.keys())).difference(pcrsInQuote))
        if len(missing) > 0:
            logger.error("%sPCRs specified in policy not in quote: %s"%(("", "v")[virtual], missing))
            return False
        return True


    #tpm_random
    def init_system_rand(self):
        RNDADDENTROPY = 0x40085203
        rand_data = self._get_tpm_rand_block()
        if common.REQUIRE_ROOT and rand_data is not None:
            try:
                t = struct.pack("ii%ds"%len(rand_data), 8, len(rand_data), rand_data)
                with open("/dev/random", mode='wb') as fp:
                    # as fp has a method fileno(), you can pass it to ioctl
                    fcntl.ioctl(fp, RNDADDENTROPY, t)
            except Exception as e:
                logger.warning("TPM randomness not added to system entropy pool: %s"%e)


    #tpm_nvram
    @abstractmethod
    def write_key_nvram(self, key):
        pass

    @abstractmethod
    def read_key_nvram(self):
        pass
