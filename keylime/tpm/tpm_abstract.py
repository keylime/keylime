import codecs
import os
import string
import typing
from abc import ABCMeta, abstractmethod

import yaml

try:
    from yaml import CSafeDumper as SafeDumper
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader, SafeDumper

from keylime import config, crypto, json, keylime_logging, measured_boot
from keylime.common import algorithms
from keylime.failure import Component, Failure
from keylime.ima import ima

logger = keylime_logging.init_logging("tpm")


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
        password = ""
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
                raise Exception(f"Invalid tpm policy pcr number: {key}")

            if int(key) == config.TPM_DATA_PCR:
                raise Exception(f"Invalid allowlist PCR number {key}, keylime uses this PCR to bind data.")
            if int(key) == config.IMA_PCR:
                raise Exception(f"Invalid allowlist PCR number {key}, this PCR is used for IMA.")

            mask = mask | (1 << int(key))

            # wrap it in a list if it is a singleton
            if isinstance(policy[key], str):
                policy[key] = [policy[key]]

            # convert all hash values to lowercase
            policy[key] = [x.lower() for x in policy[key]]

        policy["mask"] = hex(mask)
        return policy


class AbstractTPM(metaclass=ABCMeta):
    # Abstract base class
    EXIT_SUCESS = 0
    TPM_IO_ERR = 5
    EMPTYMASK = "1"
    MAX_NONCE_SIZE = 64

    # constructor
    def __init__(self, need_hw_tpm=True):
        # read the config file
        self.need_hw_tpm = need_hw_tpm
        self.global_tpmdata = None
        self.tpmrand_warned = False
        self.defaults = {}
        self.defaults["hash"] = algorithms.Hash.SHA1
        self.defaults["encrypt"] = algorithms.Encrypt.RSA
        self.defaults["sign"] = algorithms.Sign.RSASSA
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
    def get_tpm_manufacturer(self, output=None):
        pass

    @abstractmethod
    def is_emulator(self):
        pass

    def warn_emulator(self):
        if self.is_emulator():
            logger.warning("INSECURE: Keylime is using a software TPM emulator rather than a real hardware TPM.")
            logger.warning("INSECURE: The security of Keylime is currently NOT linked to a hardware root of trust.")
            logger.warning("INSECURE: Only use Keylime in this mode for testing or debugging purposes.")

    @staticmethod
    def __read_tpm_data():
        if os.path.exists("tpmdata.yml"):
            with open("tpmdata.yml", "rb") as f:
                return yaml.load(f, Loader=SafeLoader)
        else:
            return {}

    def __write_tpm_data(self):
        with os.fdopen(os.open("tpmdata.yml", os.O_WRONLY | os.O_CREAT, 0o600), "w", encoding="utf-8") as f:
            yaml.dump(self.global_tpmdata, f, Dumper=SafeDumper)

    def get_tpm_metadata(self, key):
        if self.global_tpmdata is None:
            self.global_tpmdata = AbstractTPM.__read_tpm_data()
        return self.global_tpmdata.get(key, None)

    def _set_tpm_metadata(self, key, value):
        if self.global_tpmdata is None:
            self.global_tpmdata = AbstractTPM.__read_tpm_data()

        if self.global_tpmdata.get(key, None) is not value:
            self.global_tpmdata[key] = value
            self.__write_tpm_data()

    @abstractmethod
    def tpm_init(self, self_activate=False, config_pw=None):
        pass

    # tpm_quote
    @abstractmethod
    def create_quote(self, nonce, data=None, pcrmask=EMPTYMASK, hash_alg=None, compress=False):
        pass

    @abstractmethod
    def check_quote(
        self,
        agentAttestState,
        nonce,
        data,
        quote,
        aikTpmFromRegistrar,
        tpm_policy=None,
        ima_measurement_list=None,
        allowlist=None,
        hash_alg=None,
        ima_keyrings=None,
        mb_measurement_list=None,
        mb_refstate=None,
        compressed=False,
    ):
        pass

    def START_HASH(self, algorithm=None):
        if algorithm is None:
            algorithm = self.defaults["hash"]

        alg_size = algorithm.get_size() // 4
        return "0" * alg_size

    def hashdigest(self, payload, algorithm=None):
        if algorithm is None:
            algorithm = self.defaults["hash"]

        digest = algorithm.hash(payload)
        if digest is None:
            return None
        return codecs.encode(digest, "hex").decode("utf-8")

    @abstractmethod
    def sim_extend(self, hashval_1, hashval_0=None, hash_alg=None):
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

    @staticmethod
    def __check_ima(agentAttestState, pcrval, ima_measurement_list, allowlist, ima_keyrings, boot_aggregates, hash_alg):
        failure = Failure(Component.IMA)
        logger.info("Checking IMA measurement list on agent: %s", agentAttestState.get_agent_id())
        _, ima_failure = ima.process_measurement_list(
            agentAttestState,
            ima_measurement_list.split("\n"),
            allowlist,
            pcrval=pcrval,
            ima_keyrings=ima_keyrings,
            boot_aggregates=boot_aggregates,
            hash_alg=hash_alg,
        )
        failure.merge(ima_failure)
        if not failure:
            logger.debug("IMA measurement list of agent %s validated", agentAttestState.get_agent_id())
        return failure

    @staticmethod
    def __parse_pcrs(pcrs, virtual) -> typing.Dict[int, str]:
        """Parses and validates the format of a list of PCR data"""
        output = {}
        for line in pcrs:
            tokens = line.split()
            if len(tokens) != 3:
                logger.error("Invalid %sPCR in quote: %s", ("", "v")[virtual], pcrs)
                continue
            try:
                pcr_num = int(tokens[1])
            except ValueError:
                logger.error("Invalid PCR number %s", tokens[1])
                continue
            output[pcr_num] = tokens[2].lower()

        return output

    def check_pcrs(
        self,
        agentAttestState,
        tpm_policy,
        pcrs,
        data,
        virtual,
        ima_measurement_list,
        allowlist,
        ima_keyrings,
        mb_measurement_list,
        mb_refstate_str,
        hash_alg,
    ) -> Failure:
        failure = Failure(Component.PCR_VALIDATION)
        if isinstance(tpm_policy, str):
            tpm_policy = json.loads(tpm_policy)

        pcr_allowlist = tpm_policy.copy()

        if "mask" in pcr_allowlist:
            del pcr_allowlist["mask"]
        # convert all pcr num keys to integers
        pcr_allowlist = {int(k): v for k, v in list(pcr_allowlist.items())}

        mb_policy, mb_policy_name, mb_refstate_data = measured_boot.get_policy(mb_refstate_str)
        mb_pcrs_hashes, boot_aggregates, mb_measurement_data, mb_failure = self.parse_mb_bootlog(
            mb_measurement_list, hash_alg
        )
        failure.merge(mb_failure)

        pcrs_in_quote = set()  # PCRs in quote that were already used for some kind of validation

        pcrs = AbstractTPM.__parse_pcrs(pcrs, virtual)
        pcr_nums = set(pcrs.keys())

        # Validate data PCR
        if config.TPM_DATA_PCR in pcr_nums and data is not None:
            expectedval = self.sim_extend(data, hash_alg=hash_alg)
            if expectedval != pcrs[config.TPM_DATA_PCR]:
                logger.error(
                    "%sPCR #%s: invalid bind data %s from quote does not match expected value %s",
                    ("", "v")[virtual],
                    config.TPM_DATA_PCR,
                    pcrs[config.TPM_DATA_PCR],
                    expectedval,
                )
                failure.add_event(
                    f"invalid_pcr_{config.TPM_DATA_PCR}",
                    {"got": pcrs[config.TPM_DATA_PCR], "expected": expectedval},
                    True,
                )
            pcrs_in_quote.add(config.TPM_DATA_PCR)
        else:
            logger.error(
                "Binding %sPCR #%s was not included in the quote, but is required",
                ("", "v")[virtual],
                config.TPM_DATA_PCR,
            )
            failure.add_event(
                f"missing_pcr_{config.TPM_DATA_PCR}",
                f"Data PCR {config.TPM_DATA_PCR} is missing in quote, but is required",
                True,
            )
        # Check for ima PCR
        if config.IMA_PCR in pcr_nums:
            if ima_measurement_list is None:
                logger.error("IMA PCR in policy, but no measurement list provided")
                failure.add_event(
                    f"unused_pcr_{config.IMA_PCR}", "IMA PCR in policy, but no measurement list provided", True
                )
            else:
                ima_failure = AbstractTPM.__check_ima(
                    agentAttestState,
                    pcrs[config.IMA_PCR],
                    ima_measurement_list,
                    allowlist,
                    ima_keyrings,
                    boot_aggregates,
                    hash_alg,
                )
                failure.merge(ima_failure)

            pcrs_in_quote.add(config.IMA_PCR)

        # Collect mismatched measured boot PCRs as measured_boot failures
        mb_pcr_failure = Failure(Component.MEASURED_BOOT)
        # Handle measured boot PCRs only if the parsing worked
        if not mb_failure:
            for pcr_num in set(config.MEASUREDBOOT_PCRS) & pcr_nums:
                if mb_refstate_data:
                    if not mb_measurement_list:
                        logger.error("Measured Boot PCR %d in policy, but no measurement list provided", pcr_num)
                        failure.add_event(
                            f"unused_pcr_{pcr_num}",
                            f"Measured Boot PCR {pcr_num} in policy, but no measurement list provided",
                            True,
                        )
                        continue

                    val_from_log_int = mb_pcrs_hashes.get(str(pcr_num), 0)
                    val_from_log_hex = hex(val_from_log_int)[2:]
                    val_from_log_hex_stripped = val_from_log_hex.lstrip("0")
                    pcrval_stripped = pcrs[pcr_num].lstrip("0")
                    if val_from_log_hex_stripped != pcrval_stripped:
                        logger.error(
                            "For PCR %d and hash %s the boot event log has value %r but the agent returned %r",
                            pcr_num,
                            str(hash_alg),
                            val_from_log_hex,
                            pcrs[pcr_num],
                        )
                        mb_pcr_failure.add_event(
                            f"invalid_pcr_{pcr_num}",
                            {
                                "context": "SHA256 boot event log PCR value does not match",
                                "got": pcrs[pcr_num],
                                "expected": val_from_log_hex,
                            },
                            True,
                        )

                    if pcr_num in pcr_allowlist and pcrs[pcr_num] not in pcr_allowlist[pcr_num]:
                        logger.error(
                            "%sPCR #%s: %s from quote does not match expected value %s",
                            ("", "v")[virtual],
                            pcr_num,
                            pcrs[pcr_num],
                            pcr_allowlist[pcr_num],
                        )
                        failure.add_event(
                            f"invalid_pcr_{pcr_num}",
                            {
                                "context": "PCR value is not in allowlist",
                                "got": pcrs[pcr_num],
                                "expected": pcr_allowlist[pcr_num],
                            },
                            True,
                        )
                    pcrs_in_quote.add(pcr_num)
        failure.merge(mb_pcr_failure)

        # Check the remaining non validated PCRs
        for pcr_num in pcr_nums - pcrs_in_quote:
            if pcr_num not in list(pcr_allowlist.keys()):
                logger.warning(
                    "%sPCR #%s in quote not found in %stpm_policy, skipping.",
                    ("", "v")[virtual],
                    pcr_num,
                    ("", "v")[virtual],
                )
                continue
            if pcrs[pcr_num] not in pcr_allowlist[pcr_num]:
                logger.error(
                    "%sPCR #%s: %s from quote does not match expected value %s",
                    ("", "v")[virtual],
                    pcr_num,
                    pcrs[pcr_num],
                    pcr_allowlist[pcr_num],
                )
                failure.add_event(
                    f"invalid_pcr_{pcr_num}",
                    {
                        "context": "PCR value is not in allowlist",
                        "got": pcrs[pcr_num],
                        "expected": pcr_allowlist[pcr_num],
                    },
                    True,
                )

            pcrs_in_quote.add(pcr_num)

        missing = set(pcr_allowlist.keys()) - pcrs_in_quote
        if len(missing) > 0:
            logger.error("%sPCRs specified in policy not in quote: %s", ("", "v")[virtual], missing)
            failure.add_event("missing_pcrs", {"context": "PCRs are missing in quote", "data": list(missing)}, True)

        if not mb_failure and mb_refstate_data:
            mb_policy_failure = measured_boot.evaluate_policy(
                mb_policy,
                mb_policy_name,
                mb_refstate_data,
                mb_measurement_data,
                pcrs_in_quote,
                ("", "v")[virtual],
                agentAttestState.get_agent_id(),
            )
            failure.merge(mb_policy_failure)

        return failure

    # tpm_nvram
    @abstractmethod
    def write_key_nvram(self, key):
        pass

    @abstractmethod
    def read_key_nvram(self):
        pass

    @abstractmethod
    def parse_mb_bootlog(self, mb_measurement_list: str, hash_alg: algorithms.Hash) -> dict:
        raise NotImplementedError
