import base64
import binascii
import codecs
import hashlib
import os
import re
import sys
import tempfile
import threading
import time
import typing
import zlib
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from cryptography.hazmat.primitives import serialization as crypto_serialization
from packaging.version import Version

from keylime import cert_utils, cmd_exec, config, keylime_logging
from keylime.agentstates import AgentAttestState, TPMClockInfo
from keylime.common import algorithms, retry
from keylime.common.algorithms import Hash
from keylime.elchecking.policies import RefState
from keylime.failure import Component, Failure
from keylime.ima import ima
from keylime.ima.file_signatures import ImaKeyrings
from keylime.ima.types import RuntimePolicyType
from keylime.tpm import tpm2_objects, tpm_abstract

logger = keylime_logging.init_logging("tpm")


class tpm(tpm_abstract.AbstractTPM):
    tools_version: str = ""

    tpmutilLock: threading.Lock

    def __init__(self) -> None:
        super().__init__()
        # Shared lock to serialize access to tools
        self.tpmutilLock = threading.Lock()

        self.__get_tpm2_tools()

    def __get_tpm2_tools(self) -> None:
        retDict = self.__run(["tpm2_startup", "--version"])

        code = retDict["code"]
        output = "".join(config.convert(retDict["retout"]))
        errout = "".join(config.convert(retDict["reterr"]))
        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            raise Exception(
                "Error establishing tpm2-tools version using TPM2_Startup: %s" + str(code) + ": " + str(errout)
            )

        # Extract the `version="x.x.x"` from tools
        version_str_ = re.search(r'version="([^"]+)"', output)
        if version_str_ is None:
            msg = f"Could not determine tpm2-tools version from TPM2_Startup output '{output}'"
            logger.error(msg)
            raise Exception(msg)
        version_str = version_str_.group(1)
        # Extract the full semver release number.
        tools_version = version_str.split("-")

        if Version(tools_version[0]) >= Version("5.4") or (
            # Also mark first git version that introduces the change to the tpm2_eventlog format as 5.4
            # See: https://github.com/tpm2-software/tpm2-tools/commit/c78d258b2588aee535fd17594ad2f5e808056373
            Version(tools_version[0]) == Version("5.3")
            and len(tools_version) > 1
            and int(tools_version[1]) >= 24
        ):
            logger.info("TPM2-TOOLS Version: %s", tools_version[0])
            self.tools_version = "5.4"
        elif Version(tools_version[0]) >= Version("4.2"):
            logger.info("TPM2-TOOLS Version: %s", tools_version[0])
            self.tools_version = "4.2"
        elif Version(tools_version[0]) >= Version("4.0.0"):
            logger.info("TPM2-TOOLS Version: %s", tools_version[0])
            self.tools_version = "4.0"
        elif Version(tools_version[0]) >= Version("3.2.0"):
            logger.info("TPM2-TOOLS Version: %s", tools_version[0])
            self.tools_version = "3.2"
        else:
            logger.error("TPM2-TOOLS Version %s is not supported.", tools_version[0])
            sys.exit()

    def run(self, cmd: Sequence[str]) -> cmd_exec.RetDictType:
        return self.__run(cmd, lock=False)

    def __run(
        self,
        cmd: Sequence[str],
        expectedcode: int = tpm_abstract.AbstractTPM.EXIT_SUCESS,
        raiseOnError: bool = True,
        lock: bool = True,
        outputpaths: Optional[Union[List[str], str]] = None,
    ) -> cmd_exec.RetDictType:
        # Convert single outputpath to list
        if isinstance(outputpaths, str):
            outputpaths = [outputpaths]

        numtries = 0
        while True:
            if lock:
                with self.tpmutilLock:
                    retDict = cmd_exec.run(
                        cmd=cmd, expectedcode=expectedcode, raiseOnError=False, outputpaths=outputpaths
                    )
            else:
                retDict = cmd_exec.run(cmd=cmd, expectedcode=expectedcode, raiseOnError=False, outputpaths=outputpaths)
            code = retDict["code"]
            retout = retDict["retout"]
            reterr = retDict["reterr"]

            # keep trying to get quote if a PCR race condition occurred in quote
            if cmd[0] == "tpm2_quote" and cmd_exec.list_contains_substring(
                reterr, "Error validating calculated PCR composite with quote"
            ):
                numtries += 1
                maxr = config.getint("agent", "max_retries")
                if numtries >= maxr:
                    logger.error("Agent did not return proper quote due to PCR race condition.")
                    break
                interval = config.getfloat("agent", "retry_interval")
                exponential_backoff = config.getboolean("agent", "exponential_backoff")
                next_retry = retry.retry_time(exponential_backoff, interval, numtries, logger)
                logger.info(
                    "Failed to get quote %d/%d times, trying again in %f seconds...", numtries, maxr, next_retry
                )
                time.sleep(next_retry)
                continue

            break

        # Don't bother continuing if TPM call failed and we're raising on error
        if code != expectedcode and raiseOnError:
            raise Exception(
                f"Command: {cmd} returned {code}, expected {expectedcode}, output {retout}, stderr {reterr}"
            )

        return retDict

    def encryptAIK(self, uuid: str, ek_tpm: bytes, aik_tpm: bytes) -> Optional[Tuple[bytes, str]]:
        if ek_tpm is None or aik_tpm is None:
            logger.error("Missing parameters for encryptAIK")
            return None

        aik_name = tpm2_objects.get_tpm2b_public_name(aik_tpm)

        efd = keyfd = blobfd = -1
        ekFile = None
        challengeFile = None
        keyblob = None
        blobpath = None

        try:
            # write out the public EK
            efd, etemp = tempfile.mkstemp()
            with open(etemp, "wb") as ekFile:
                ekFile.write(ek_tpm)

            # write out the challenge
            challenge_str = tpm_abstract.TPM_Utilities.random_password(32)
            challenge = challenge_str.encode()
            keyfd, keypath = tempfile.mkstemp()
            with open(keypath, "wb") as challengeFile:
                challengeFile.write(challenge)

            # create temp file for the blob
            blobfd, blobpath = tempfile.mkstemp()
            command = [
                "tpm2_makecredential",
                "-T",
                "none",
                "-e",
                ekFile.name,
                "-s",
                challengeFile.name,
                "-n",
                aik_name,
                "-o",
                blobpath,
            ]
            self.__run(command, lock=False)

            logger.info("Encrypting AIK for UUID %s", uuid)

            # read in the blob
            with open(blobpath, "rb") as f:
                keyblob = base64.b64encode(f.read())

            # read in the aes key
            key = base64.b64encode(challenge).decode("utf-8")

        except Exception as e:
            logger.error("Error encrypting AIK: %s", str(e))
            logger.exception(e)
            raise
        finally:
            for fd in [efd, keyfd, blobfd]:
                if fd >= 0:
                    os.close(fd)
            for fi in [ekFile, challengeFile]:
                if fi is not None:
                    os.remove(fi.name)
            if blobpath is not None:
                os.remove(blobpath)

        return (keyblob, key)

    def verify_ek(self, ekcert: bytes, tpm_cert_store: str) -> bool:
        """Verify that the provided EK certificate is signed by a trusted root
        :param ekcert: The Endorsement Key certificate in DER format
        :returns: True if the certificate can be verified, false otherwise
        """
        return cert_utils.verify_ek(ekcert, tpm_cert_store)

    # tpm_quote
    def __tpm2_checkquote(
        self, pubaik: str, nonce: str, quoteFile: str, sigFile: str, pcrFile: str, hash_alg: Union[Hash, str]
    ) -> cmd_exec.RetDictType:
        nonce = bytes(nonce, encoding="utf8").hex()
        if self.tools_version == "3.2":
            command = [
                "tpm2_checkquote",
                "-c",
                pubaik,
                "-m",
                quoteFile,
                "-s",
                sigFile,
                "-p",
                pcrFile,
                "-G",
                hash_alg,
                "-q",
                nonce,
            ]
        else:
            # versions >= 4.0
            command = [
                "tpm2_checkquote",
                "-u",
                pubaik,
                "-m",
                quoteFile,
                "-s",
                sigFile,
                "-f",
                pcrFile,
                "-g",
                hash_alg,
                "-q",
                nonce,
            ]

        retDict = self.__run(command, lock=False)
        return retDict

    def __tpm2_printquote(self, quoteFile: str) -> cmd_exec.RetDictType:
        command = ["tpm2_print", "-t", "TPMS_ATTEST", quoteFile]
        retDict = self.__run(command, lock=False)
        return retDict

    def _tpm2_printquote(self, quote: str, compressed: bool) -> Tuple[Optional[List[bytes]], bool]:
        """Get TPM timestamp info from quote
        :param quote: quote data in the format 'r<b64-compressed-quoteblob>:<b64-compressed-sigblob>:<b64-compressed-pcrblob>
        :param compressed: if the quote data is compressed with zlib or not
        :returns: Returns the 'retout' from running tpm2_print and True in case of success, None and False in case of error.
        This function throws an Exception on bad input.
        """

        if quote[0] != "r":
            raise Exception(f"Invalid quote type {quote[0]}")
        quote = quote[1:]

        quote_tokens = quote.split(":")
        if len(quote_tokens) < 3:
            raise Exception(f"Quote is not compound! {quote}")

        quoteblob = base64.b64decode(quote_tokens[0])

        if compressed:
            logger.warning("Decompressing quote data which is unsafe!")
            quoteblob = zlib.decompress(quoteblob)

        qfd = -1
        quoteFile = None

        try:
            # write out quote
            qfd, qtemp = tempfile.mkstemp()
            with open(qtemp, "wb") as quoteFile:
                quoteFile.write(quoteblob)

            retDict = self.__tpm2_printquote(quoteFile.name)
            retout = retDict["retout"]
            reterr = retDict["reterr"]
            code = retDict["code"]
        except Exception as e:
            logger.error("Error printing quote: %s", str(e))
            logger.exception(e)
            return None, False
        finally:
            for fd in [qfd]:
                if fd >= 0:
                    os.close(fd)
            for fi in [quoteFile]:
                if fi is not None:
                    os.remove(fi.name)

        if len(retout) < 1 or code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            logger.error("Failed to print quote info, output: %s", reterr)
            return None, False

        return retout, True

    def _tpm2_checkquote(
        self, aikTpmFromRegistrar: str, quote: str, nonce: str, hash_alg: Union[Hash, str], compressed: bool
    ) -> Tuple[Optional[List[bytes]], bool]:
        """Write the files from data returned from tpm2_quote for running tpm2_checkquote
        :param aikTpmFromRegistrar: AIK used to generate the quote and is needed for verifying it now.
        :param quote: quote data in the format 'r<b64-compressed-quoteblob>:<b64-compressed-sigblob>:<b64-compressed-pcrblob>
        :param nonce: nonce that was used to create the quote
        :param hash_alg: the hash algorithm that was used
        :param compressed: if the quote data is compressed with zlib or not
        :returns: Returns the 'retout' from running tpm2_checkquote and True in case of success, None and False in case of error.
        This function throws an Exception on bad input.
        """
        aikFromRegistrar = tpm2_objects.pubkey_from_tpm2b_public(
            base64.b64decode(aikTpmFromRegistrar),
        ).public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if quote[0] != "r":
            raise Exception(f"Invalid quote type {quote[0]}")
        quote = quote[1:]

        quote_tokens = quote.split(":")
        if len(quote_tokens) < 3:
            raise Exception(f"Quote is not compound! {quote}")

        quoteblob = base64.b64decode(quote_tokens[0])
        sigblob = base64.b64decode(quote_tokens[1])
        pcrblob = base64.b64decode(quote_tokens[2])

        if compressed:
            logger.warning("Decompressing quote data which is unsafe!")
            quoteblob = zlib.decompress(quoteblob)
            sigblob = zlib.decompress(sigblob)
            pcrblob = zlib.decompress(pcrblob)

        qfd = sfd = pfd = afd = -1
        quoteFile = None
        aikFile = None
        sigFile = None
        pcrFile = None

        try:
            # write out quote
            qfd, qtemp = tempfile.mkstemp()
            with open(qtemp, "wb") as quoteFile:
                quoteFile.write(quoteblob)

            # write out sig
            sfd, stemp = tempfile.mkstemp()
            with open(stemp, "wb") as sigFile:
                sigFile.write(sigblob)

            # write out pcr
            pfd, ptemp = tempfile.mkstemp()
            with open(ptemp, "wb") as pcrFile:
                pcrFile.write(pcrblob)

            afd, atemp = tempfile.mkstemp()
            with open(atemp, "wb") as aikFile:
                aikFile.write(aikFromRegistrar)

            retDict = self.__tpm2_checkquote(aikFile.name, nonce, quoteFile.name, sigFile.name, pcrFile.name, hash_alg)
            retout = retDict["retout"]
            reterr = retDict["reterr"]
            code = retDict["code"]
        except Exception as e:
            logger.error("Error verifying quote: %s", str(e))
            logger.exception(e)
            return None, False
        finally:
            for fd in [qfd, sfd, pfd, afd]:
                if fd >= 0:
                    os.close(fd)
            for fi in [aikFile, quoteFile, sigFile, pcrFile]:
                if fi is not None:
                    os.remove(fi.name)

        if len(retout) < 1 or code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            logger.error("Failed to validate signature, output: %s", reterr)
            return None, False

        return retout, True

    def check_quote(
        self,
        agentAttestState: AgentAttestState,
        nonce: str,
        data: str,
        quote: str,
        aikTpmFromRegistrar: str,
        tpm_policy: Optional[Union[str, Dict[str, Any]]] = None,
        ima_measurement_list: Optional[str] = None,
        runtime_policy: Optional[RuntimePolicyType] = None,
        hash_alg: Optional[Hash] = None,
        ima_keyrings: Optional[ImaKeyrings] = None,
        mb_measurement_list: Optional[str] = None,
        mb_refstate: Optional[str] = None,
        compressed: bool = False,
    ) -> Failure:
        if tpm_policy is None:
            tpm_policy = {}

        if runtime_policy is None:
            runtime_policy = ima.EMPTY_RUNTIME_POLICY

        agent_id = agentAttestState.agent_id

        failure = Failure(Component.QUOTE_VALIDATION)
        if hash_alg is None:
            failure.add_event("hash_alg_missing", "Hash algorithm cannot be empty", False)
            return failure

        # First and foremost, the quote needs to be validated
        retout, success = self._tpm2_checkquote(aikTpmFromRegistrar, quote, nonce, hash_alg, compressed)
        if not success:
            # If the quote validation fails we will skip all other steps therefore this failure is irrecoverable.
            failure.add_event(
                "quote_validation", {"message": "Quote data validation using tpm2-tools", "data": retout}, False
            )
            return failure

        # Only after validating the quote, the TPM clock information can be extracted from it.
        clock_failure, current_clock_info = self.check_quote_timing(
            agentAttestState.get_tpm_clockinfo(), quote, compressed
        )
        if clock_failure:
            failure.add_event(
                "quote_validation",
                {"message": "Validation of clockinfo from quote using tpm2-tools", "data": clock_failure},
                False,
            )
            return failure
        if current_clock_info:
            agentAttestState.set_tpm_clockinfo(current_clock_info)

        pcrs = []
        jsonout = config.yaml_to_dict(retout, logger=logger)
        if jsonout is None:
            failure.add_event(
                "quote_validation",
                {"message": "YAML parsing failed for quote validation using tpm2-tools.", "data": retout},
                False,
            )
            return failure
        if "pcrs" in jsonout:
            # The hash algorithm might be in the YAML output but does not contain any data, so we also check that.
            if hash_alg in jsonout["pcrs"] and jsonout["pcrs"][hash_alg] is not None:
                alg_size = hash_alg.get_size() // 4
                for pcrval, hashval in jsonout["pcrs"][hash_alg].items():
                    pcrs.append(f"PCR {pcrval} {hashval:0{alg_size}x}")

        if len(pcrs) == 0:
            logger.warning(
                "Quote for agent %s does not contain any PCRs. Make sure that the TPM supports %s PCR banks",
                agent_id,
                str(hash_alg),
            )

        return self.check_pcrs(
            agentAttestState,
            tpm_policy,
            pcrs,
            data,
            ima_measurement_list,
            runtime_policy,
            ima_keyrings,
            mb_measurement_list,
            mb_refstate,
            hash_alg,
        )

    def check_quote_timing(
        self, previous_clockinfo: TPMClockInfo, quote: str, compressed: bool
    ) -> Tuple[Optional[str], Optional[TPMClockInfo]]:
        # Sanity check quote clock information

        current_clockinfo = None

        retout, success = self._tpm2_printquote(quote, compressed)
        if not success:
            return "tpm2_print failed with " + str(retout), current_clockinfo

        tpm_data_str_dict = config.yaml_to_dict(retout, add_newlines=False, logger=logger)
        if tpm_data_str_dict is None:
            return "yaml output of tpm2_print could not be parsed!", current_clockinfo

        tentative_current_clockinfo = TPMClockInfo.from_dict(tpm_data_str_dict)

        resetdiff = tentative_current_clockinfo.resetcount - previous_clockinfo.resetcount
        restartdiff = tentative_current_clockinfo.restartcount - previous_clockinfo.restartcount

        if resetdiff < 0:
            return "resetCount value decreased on TPM between two consecutive quotes", current_clockinfo

        if restartdiff < 0:
            return "restartCount value decreased on TPM between two consecutive quotes", current_clockinfo

        if tentative_current_clockinfo.safe != 1:
            return "clock safe flag is disabled", current_clockinfo

        if not (resetdiff and restartdiff):
            if tentative_current_clockinfo.clock - previous_clockinfo.clock <= 0:
                return (
                    "clock timestamp did issued by TPM did not increase between two consecutive quotes",
                    current_clockinfo,
                )

            current_clockinfo = tentative_current_clockinfo

        return None, current_clockinfo

    def sim_extend(self, hashval_1: str, hash_alg: Hash) -> str:
        hashval_0 = self.START_HASH(hash_alg)

        # compute expected value  H(0|H(data))
        hdata = self.hashdigest(hashval_1.encode("utf-8"), hash_alg)
        assert hdata is not None
        hext = self.hashdigest(
            codecs.decode(hashval_0, "hex_codec") + codecs.decode(hdata, "hex_codec"),
            hash_alg,
        )
        assert hext is not None
        return hext.lower()

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def __unescape_eventlog(log: Dict) -> None:  # type: ignore
        """
        Newer versions of tpm2-tools escapes the YAML output and including the trailing null byte.
        See: https://github.com/tpm2-software/tpm2-tools/commit/c78d258b2588aee535fd17594ad2f5e808056373
        This converts it back to an unescaped string.
        Example:
            '"MokList\\0"' -> 'MokList'
        """
        if tpm.tools_version in ["3.2", "4.0", "4.2"]:
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
            if isinstance(data, str):
                if data.startswith('"') and data.endswith('"'):
                    data = data[1:-1]
                    for orig, escaped in escaped_chars:
                        data = data.replace(escaped, orig)
                    data = data.rstrip("\0")
            elif isinstance(data, dict):
                for key, value in data.items():
                    data[key] = recursive_unescape(value)  # type: ignore
            elif isinstance(data, list):
                for pos, item in enumerate(data):
                    data[pos] = recursive_unescape(item)  # type: ignore
            return data

        recursive_unescape(log)  # type: ignore

    def parse_binary_bootlog(self, log_bin: bytes) -> typing.Tuple[Failure, typing.Optional[Dict[str, Any]]]:
        """Parse and enrich a BIOS boot log

        The input is the binary log.
        The output is the result of parsing and applying other conveniences."""
        failure = Failure(Component.MEASURED_BOOT, ["parser"])
        with tempfile.NamedTemporaryFile() as log_bin_file:
            log_bin_file.write(log_bin)
            log_bin_file.seek(0)
            log_bin_filename = log_bin_file.name
            try:
                retDict_tpm2 = self.__run(["tpm2_eventlog", "--eventlog-version=2", log_bin_filename])
            except Exception:
                failure.add_event("tpm2_eventlog", "running tpm2_eventlog failed", True)
                return failure, None
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
            from keylime import tpm_bootlog_enrich
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
        tpm.__stringify_pcr_keys(log_parsed_data)
        tpm.__add_boot_aggregate(log_parsed_data)
        tpm.__unescape_eventlog(log_parsed_data)
        return failure, log_parsed_data

    def _parse_mb_bootlog(self, log_b64: str) -> typing.Tuple[Failure, typing.Optional[Dict[str, Any]]]:
        """Parse and enrich a BIOS boot log

        The input is the base64 encoding of a binary log.
        The output is the result of parsing and applying other conveniences."""
        failure = Failure(Component.MEASURED_BOOT, ["parser"])
        try:
            log_bin = base64.b64decode(log_b64, validate=True)
            failure_mb, result = self.parse_binary_bootlog(log_bin)
            if failure_mb:
                failure.merge(failure_mb)
                result = None
        except binascii.Error:
            failure.add_event("log.base64decode", "Measured boot log could not be decoded", True)
            result = None
        return failure, result

    def parse_mb_bootlog(
        self, mb_measurement_list: Optional[str], hash_alg: algorithms.Hash
    ) -> typing.Tuple[Dict[str, int], typing.Optional[Dict[str, List[str]]], RefState, Failure]:
        """Parse the measured boot log and return its object and the state of the PCRs
        :param mb_measurement_list: The measured boot measurement list
        :param hash_alg: the hash algorithm that should be used for the PCRs
        :returns: Returns a map of the state of the PCRs, measured boot data object and True for success
                  and False in case an error occurred
        """
        failure = Failure(Component.MEASURED_BOOT, ["parser"])
        if mb_measurement_list:
            failure_mb, mb_measurement_data = self._parse_mb_bootlog(mb_measurement_list)
            if not mb_measurement_data:
                failure.merge(failure_mb)
                logger.error("Unable to parse measured boot event log. Check previous messages for a reason for error.")
                return {}, None, {}, failure
            log_pcrs = mb_measurement_data.get("pcrs")
            if not isinstance(log_pcrs, dict):
                logger.error("Parse of measured boot event log has unexpected value for .pcrs: %r", log_pcrs)
                failure.add_event("invalid_pcrs", {"got": log_pcrs}, True)
                return {}, None, {}, failure
            pcr_hashes = log_pcrs.get(str(hash_alg))
            if (not isinstance(pcr_hashes, dict)) or not pcr_hashes:
                logger.error(
                    "Parse of measured boot event log has unexpected value for .pcrs.%s: %r", str(hash_alg), pcr_hashes
                )
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
