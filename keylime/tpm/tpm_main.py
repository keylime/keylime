import base64
import binascii
import codecs
import collections
import hashlib
import os
import re
import sys
import tempfile
import threading
import time
import typing
import zlib
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, cast

from cryptography.hazmat.primitives import serialization as crypto_serialization
from packaging.version import Version

from keylime import cert_utils, cmd_exec, config, keylime_logging, secure_mount
from keylime.agentstates import AgentAttestState, TPMClockInfo
from keylime.common import algorithms, retry
from keylime.common.algorithms import Hash
from keylime.failure import Component, Failure
from keylime.ima.file_signatures import ImaKeyrings
from keylime.tpm import tpm2_objects, tpm_abstract

logger = keylime_logging.init_logging("tpm")


def _get_cmd_env() -> Dict[str, str]:
    env = os.environ.copy()
    if "TPM2TOOLS_TCTI" not in env:
        # Don't clobber existing setting (if present)
        env["TPM2TOOLS_TCTI"] = "device:/dev/tpmrm0"
        # env['TPM2TOOLS_TCTI'] = 'tabrmd:bus_name=com.intel.tss2.Tabrmd'
        # Other (not recommended) options are direct emulator and chardev communications:
        # env['TPM2TOOLS_TCTI'] = 'mssim:port=2321'
        # env['TPM2TOOLS_TCTI'] = 'device:/dev/tpm0'
    return env


class tpm(tpm_abstract.AbstractTPM):
    VERSION: int = 2
    tools_version: str = ""

    tpmutilLock: threading.Lock

    def __init__(self, need_hw_tpm: bool = False) -> None:
        tpm_abstract.AbstractTPM.__init__(self, need_hw_tpm)

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

    def __get_tpm_algorithms(self) -> None:
        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_getcap", "-c", "algorithms"])
        else:
            retDict = self.__run(["tpm2_getcap", "algorithms"])

        output = config.convert(retDict["retout"])
        errout = config.convert(retDict["reterr"])
        code = retDict["code"]

        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            raise Exception("get_tpm_algorithms failed with code " + str(code) + ": " + str(errout))

        if self.tools_version == "3.2":
            # output, human-readable -> json
            output = "".join(output)
            output = re.sub(r"TPMA_ALGORITHM for ALG_ID: 0x[0-9a-f]+\s+-\s+([a-z0-9_]+)", r"\1:", output)
            output = output.replace("set", "1")
            output = output.replace("clear", "0")
            output = [output]

        retyaml = config.yaml_to_dict(output, logger=logger)
        if retyaml is None:
            logger.warning("Could not read YAML output of tpm2_getcap.")
            return
        for algorithm, details in retyaml.items():
            if details["asymmetric"] == 1 and details["object"] == 1 and algorithms.Encrypt.is_recognized(algorithm):
                self.supported["encrypt"].add(algorithm)
            elif details["hash"] == 1 and algorithms.Hash.is_recognized(algorithm):
                self.supported["hash"].add(algorithm)
            elif details["asymmetric"] == 1 and details["signing"] == 1 and algorithms.Sign.is_recognized(algorithm):
                self.supported["sign"].add(algorithm)

    def __get_pcrs(self):
        """Gets which PCRs are enabled with which hash algorithm"""
        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_getcap", "-c", "pcrs"])
        else:
            retDict = self.__run(["tpm2_getcap", "pcrs"])

        output = config.convert(retDict["retout"])
        errout = config.convert(retDict["reterr"])
        code = retDict["code"]

        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            raise Exception("get_tpm_algorithms failed with code " + str(code) + ": " + str(errout))

        retyaml = config.yaml_to_dict(output, logger=logger)
        pcrs = {}
        if retyaml is None:
            logger.warning("Could not read YAML output of tpm2_getcap.")
            return pcrs
        if "selected-pcrs" in retyaml:
            pcrs = collections.ChainMap(*retyaml["selected-pcrs"])
        return pcrs

    def run(self, cmd: Sequence[str]) -> cmd_exec.RetDictType:
        return self.__run(cmd, lock=False)

    def __run(
        self,
        cmd: Sequence[str],
        expectedcode: int = tpm_abstract.AbstractTPM.EXIT_SUCESS,
        raiseOnError: bool = True,
        lock: bool = True,
        outputpaths: Optional[Union[List, str]] = None,
    ) -> cmd_exec.RetDictType:
        env = _get_cmd_env()

        # Convert single outputpath to list
        if isinstance(outputpaths, str):
            outputpaths = [outputpaths]

        numtries = 0
        while True:
            if lock:
                with self.tpmutilLock:
                    retDict = cmd_exec.run(
                        cmd=cmd, expectedcode=expectedcode, raiseOnError=False, outputpaths=outputpaths, env=env
                    )
            else:
                retDict = cmd_exec.run(
                    cmd=cmd, expectedcode=expectedcode, raiseOnError=False, outputpaths=outputpaths, env=env
                )
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

    # tpm_initialize
    def __startup_tpm(self) -> None:
        retDict = self.__run(["tpm2_startup", "-c"])
        errout = config.convert(retDict["reterr"])
        code = retDict["code"]
        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            raise Exception("Error initializing emulated TPM with TPM2_Startup: %s" + str(code) + ": " + str(errout))

    def __create_ek(self, asym_alg: Optional[str] = None):
        # this function is intended to be idempotent
        if asym_alg is None:
            asym_alg = self.defaults["encrypt"]

        current_handle = cast(int, self.get_tpm_metadata("ek_handle"))
        owner_pw = self.get_tpm_metadata("owner_pw")

        # clear out old handle before starting again (give idempotence)
        if current_handle is not None and owner_pw is not None:
            logger.info("Flushing old ek handle: %s", hex(current_handle))
            if self.tools_version == "3.2":
                retDict = self.__run(["tpm2_getcap", "-c", "handles-persistent"], raiseOnError=False)
            else:
                retDict = self.__run(["tpm2_getcap", "handles-persistent"], raiseOnError=False)
            output = retDict["retout"]
            reterr = retDict["reterr"]
            code = retDict["code"]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_getcap failed with code " + str(code) + ": " + str(reterr))

            outjson = config.yaml_to_dict(output, logger=logger)
            if outjson is not None and hex(current_handle) in outjson:
                if self.tools_version == "3.2":
                    cmd = ["tpm2_evictcontrol", "-A", "o", "-H", hex(current_handle), "-P", owner_pw]
                    retDict = self.__run(cmd, raiseOnError=False)
                else:
                    cmd = ["tpm2_evictcontrol", "-C", "o", "-c", hex(current_handle), "-P", owner_pw]
                    retDict = self.__run(cmd, raiseOnError=False)
                output = retDict["retout"]
                reterr = retDict["reterr"]
                code = retDict["code"]

                if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                    logger.info(
                        "Failed to flush old ek handle: %s.  Code %s: %s", hex(current_handle), str(code), str(reterr)
                    )

                self._set_tpm_metadata("ek_handle", None)
                self._set_tpm_metadata("ek_tpm", None)
                self._set_tpm_metadata("ek_pw", None)

        # make sure an ownership pw is set
        if owner_pw is None:
            owner_pw = tpm_abstract.TPM_Utilities.random_password(20)
            self._set_tpm_metadata("owner_pw", owner_pw)
        ek_pw = tpm_abstract.TPM_Utilities.random_password(20)

        # create a new ek
        with tempfile.NamedTemporaryFile() as tmppath:
            # TODO(kaifeng) Missing else here for other versions
            if self.tools_version == "3.2":
                command = [
                    "tpm2_getpubek",
                    "-H",
                    "0x81010007",
                    "-g",
                    asym_alg,
                    "-f",
                    tmppath.name,
                    "-P",
                    ek_pw,
                    "-o",
                    owner_pw,
                    "-e",
                    owner_pw,
                ]
            elif self.tools_version == "4.0":
                command = [
                    "tpm2_createek",
                    "-c",
                    "-",
                    "-G",
                    asym_alg,
                    "-u",
                    tmppath.name,
                    "-p",
                    ek_pw,
                    "-w",
                    owner_pw,
                    "-P",
                    owner_pw,
                ]
            else:
                # version 4.2 or later
                command = [
                    "tpm2_createek",
                    "-c",
                    "-",
                    "-G",
                    asym_alg,
                    "-u",
                    tmppath.name,
                    "-w",
                    owner_pw,
                    "-P",
                    owner_pw,
                ]

            retDict = self.__run(command, raiseOnError=False, outputpaths=tmppath.name)
            output = retDict["retout"]
            reterr = retDict["reterr"]
            code = retDict["code"]
            ek_tpm = retDict["fileouts"][tmppath.name]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("createek failed with code " + str(code) + ": " + str(reterr))

            if self.tools_version == "3.2":
                handle = int(0x81010007)
            else:
                handle = None
                retyaml = config.yaml_to_dict(output, logger=logger)
                if retyaml is None:
                    raise Exception("Could not read YAML output of tpm2_createek.")
                if "persistent-handle" in retyaml:
                    handle = retyaml["persistent-handle"]

            # Make sure that all transient objects are flushed
            self.__run(["tpm2_flushcontext", "-t"], raiseOnError=False)

            self._set_tpm_metadata("ek_handle", handle)
            self._set_tpm_metadata("ek_pw", ek_pw)
            self._set_tpm_metadata("ek_tpm", base64.b64encode(ek_tpm))
            self._set_tpm_metadata("ek_alg", asym_alg)

    def __use_ek(self, ek_handle_str: str, config_pw: Optional[str]) -> None:
        ek_handle = int(ek_handle_str, 16)
        logger.info("Using an already created ek with handle: %s", hex(ek_handle))

        self._set_tpm_metadata("owner_pw", config_pw)

        with tempfile.NamedTemporaryFile() as tmppath:
            if self.tools_version == "3.2":
                cmd = ["tpm2_readpublic", "-H", hex(ek_handle), "-o", tmppath.name, "-f", "tss"]
                retDict = self.__run(cmd, raiseOnError=False, outputpaths=tmppath.name)
            else:
                cmd = ["tpm2_readpublic", "-c", hex(ek_handle), "-o", tmppath.name, "-f", "tss"]
                retDict = self.__run(cmd, raiseOnError=False, outputpaths=tmppath.name)

            reterr = retDict["reterr"]
            code = retDict["code"]
            ek_tpm = retDict["fileouts"][tmppath.name]
            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_readpublic failed with code " + str(code) + ": " + str(reterr))
            self._set_tpm_metadata("ek_tpm", base64.b64encode(ek_tpm))

        self._set_tpm_metadata("ek_handle", int(ek_handle))

    def __take_ownership(self, config_pw: Optional[str]) -> None:
        # if no ownerpassword
        if not config_pw or config_pw == "generate":
            logger.info("Generating random TPM owner password")
            owner_pw = tpm_abstract.TPM_Utilities.random_password(20)
        else:
            logger.info("Taking ownership with config provided TPM owner password")
            owner_pw = config_pw

        logger.debug("Removing all saved sessions from TPM")
        retDict = self.__run(["tpm2_flushcontext", "-s"], raiseOnError=False)

        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_takeownership", "-c"], raiseOnError=False)
            retDict = self.__run(["tpm2_takeownership", "-o", owner_pw, "-e", owner_pw], raiseOnError=False)
        else:
            retDict = self.__run(["tpm2_changeauth", "-c", "o", owner_pw], raiseOnError=False)
            retDict = self.__run(["tpm2_changeauth", "-c", "e", owner_pw], raiseOnError=False)

        code = retDict["code"]
        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            # if we fail, see if already owned with this pw
            if self.tools_version == "3.2":
                retDict = self.__run(
                    ["tpm2_takeownership", "-o", owner_pw, "-e", owner_pw, "-O", owner_pw, "-E", owner_pw],
                    raiseOnError=False,
                )
            else:
                retDict = self.__run(["tpm2_changeauth", "-c", "o", "-p", owner_pw, owner_pw], raiseOnError=False)
                retDict = self.__run(["tpm2_changeauth", "-c", "e", "-p", owner_pw, owner_pw], raiseOnError=False)

            reterr = retDict["reterr"]
            code = retDict["code"]
            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                # ut-oh, already owned but not with provided pw!
                raise Exception("Owner password unknown, TPM reset required. Code %s" + str(code) + ": " + str(reterr))

        self._set_tpm_metadata("owner_pw", owner_pw)
        logger.info("TPM Owner password confirmed: %s", owner_pw)

    def __get_pub_ek(self) -> None:  # assumes that owner_pw is correct at this point
        handle = cast(int, self.get_tpm_metadata("ek_handle"))
        if handle is None:
            raise Exception("create_ek has not been run yet?")
        # make a temp file for the output
        with tempfile.NamedTemporaryFile() as tmppath:
            # generates pubek.pem
            if self.tools_version == "3.2":
                cmd = ["tpm2_readpublic", "-H", hex(handle), "-o", tmppath.name]
                retDict = self.__run(cmd, raiseOnError=False, outputpaths=tmppath.name)
            else:
                cmd = ["tpm2_readpublic", "-c", hex(handle), "-o", tmppath.name]
                retDict = self.__run(cmd, raiseOnError=False, outputpaths=tmppath.name)

            reterr = retDict["reterr"]
            code = retDict["code"]
            ek = retDict["fileouts"][tmppath.name]
            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_readpublic failed with code " + str(code) + ": " + str(reterr))

        self._set_tpm_metadata("ek_tpm", base64.b64encode(ek))

    def __create_aik(
        self, asym_alg: Optional[str] = None, hash_alg: Optional[str] = None, sign_alg: Optional[str] = None
    ):
        if hash_alg is None:
            hash_alg = self.defaults["hash"]
        if asym_alg is None:
            asym_alg = self.defaults["encrypt"]
        if sign_alg is None:
            sign_alg = self.defaults["sign"]

        owner_pw = self.get_tpm_metadata("owner_pw")

        # clear out old handle before starting again (give idempotence)
        aik_handle = self.get_tpm_metadata("aik_handle")
        if aik_handle is not None:
            if self.tools_version == "3.2":
                logger.info("Flushing old ak handle: %s", hex(cast(int, aik_handle)))
                retDict = self.__run(["tpm2_getcap", "-c", "handles-persistent"], raiseOnError=False)
            else:
                logger.info("Flushing old ak handle: %s", aik_handle)
                retDict = self.__run(["tpm2_getcap", "handles-persistent"], raiseOnError=False)
            output = config.convert(retDict["retout"])
            errout = config.convert(retDict["reterr"])
            code = retDict["code"]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_getcap failed with code " + str(code) + ": " + str(errout))

            if self.tools_version == "3.2":
                # output, human-readable -> json
                output = "".join(output)
                output = output.replace("0x", " - 0x")
                output = [output]

            outjson = config.yaml_to_dict(output, logger=logger)
            if self.tools_version == "3.2":
                evict_it = outjson is not None and aik_handle in outjson
            else:
                evict_it = os.path.exists(aik_handle)

            if evict_it:
                if self.tools_version == "3.2":
                    cmd = ["tpm2_evictcontrol", "-A", "o", "-H", hex(cast(int, aik_handle)), "-P", owner_pw]
                    retDict = self.__run(cmd, raiseOnError=False)
                else:
                    cmd = ["tpm2_evictcontrol", "-C", "o", "-c", aik_handle, "-P", owner_pw]
                    retDict = self.__run(cmd, raiseOnError=False)
                    os.remove(cast(str, aik_handle))

                output = retDict["retout"]
                reterr = retDict["reterr"]
                code = retDict["code"]

                if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                    if self.tools_version == "3.2":
                        logger.info(
                            "Failed to flush old ak handle: %s.  Code %s: %s",
                            hex(cast(int, aik_handle)),
                            str(code),
                            str(reterr),
                        )
                    else:
                        logger.info(
                            "Failed to flush old ak handle: %s.  Code %s: %s", aik_handle, str(code), str(reterr)
                        )

                self._set_tpm_metadata("aik_pw", None)
                self._set_tpm_metadata("aik_tpm", None)
                self._set_tpm_metadata("aik_handle", None)

        logger.debug("Creating a new AIK identity")

        # We need an ek handle to make an aik
        ek_handle = cast(int, self.get_tpm_metadata("ek_handle"))
        if ek_handle is None:
            raise Exception("Failed to create AIK, since EK has not yet been created!")

        aik_pw = tpm_abstract.TPM_Utilities.random_password(20)
        # make a temp file for the output
        secfd = 0
        with tempfile.NamedTemporaryFile() as akpubfile:
            secpath = ""
            if self.tools_version in ["4.0", "4.2", "5.4"]:
                # ok lets write out the key now
                secdir = secure_mount.mount()  # confirm that storage is still securely mounted
                secfd, secpath = tempfile.mkstemp(dir=secdir)

            if self.tools_version == "3.2":
                command = [
                    "tpm2_getpubak",
                    "-E",
                    hex(ek_handle),
                    "-k",
                    "0x81010008",
                    "-g",
                    asym_alg,
                    "-D",
                    hash_alg,
                    "-s",
                    sign_alg,
                    "-f",
                    akpubfile.name,
                    "-e",
                    owner_pw,
                    "-P",
                    aik_pw,
                    "-o",
                    owner_pw,
                ]
            else:
                command = [
                    "tpm2_createak",
                    "-C",
                    hex(ek_handle),
                    "-c",
                    secpath,
                    "-G",
                    asym_alg,
                    "-g",
                    hash_alg,
                    "-s",
                    sign_alg,
                    "-u",
                    akpubfile.name,
                    "-p",
                    aik_pw,
                    "-P",
                    owner_pw,
                ]
            retDict = self.__run(command, outputpaths=akpubfile.name)
            if secfd >= 0:
                os.close(secfd)
            retout = retDict["retout"]
            reterr = retDict["reterr"]
            code = retDict["code"]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_createak failed with code " + str(code) + ": " + str(reterr))

            jsonout = config.yaml_to_dict(retout, logger=logger)
            if jsonout is None:
                raise Exception(
                    "unable to parse YAML output of tpm2_createak. Is your tpm2-tools installation up to date?"
                )
            aik_tpm = retDict["fileouts"][akpubfile.name]
            if aik_tpm == "":
                raise Exception(
                    "unable to read public aik from create identity.  Is your tpm2-tools installation up to date?"
                )
            self._set_tpm_metadata("aik_tpm", base64.b64encode(aik_tpm))

        if self.tools_version == "3.2":
            if "loaded-key" not in jsonout or "name" not in jsonout["loaded-key"]:
                raise Exception("tpm2_createak failed to create aik: return " + str(reterr))

            handle = int(0x81010008)

            # get and persist the pem (not returned by tpm2_getpubak)
            self._set_tpm_metadata("aik_handle", handle)
        else:
            if "loaded-key" not in jsonout:
                raise Exception("tpm2_createak failed to create aik: return " + str(reterr))

            handle = secpath

            # persist the pem
            self._set_tpm_metadata("aik_handle", handle)

        # Make sure that all transient objects are flushed
        self.__run(["tpm2_flushcontext", "-t"], raiseOnError=False)

        # persist common results
        self._set_tpm_metadata("aik_pw", aik_pw)

    def flush_keys(self) -> None:
        logger.debug("Flushing keys from TPM...")
        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_getcap", "-c", "handles-persistent"])
        else:
            retDict = self.__run(["tpm2_getcap", "handles-persistent"])

        retout = config.convert(retDict["retout"])
        errout = config.convert(retDict["reterr"])
        code = retDict["code"]

        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            logger.debug("tpm2_getcap failed with code %s: %s", str(code), str(errout))

        if self.tools_version == "3.2":
            # output, human-readable -> json
            retout = "".join(retout)
            retout = retout.replace("0x", " - 0x")
            retout = [retout]

        owner_pw = cast(str, self.get_tpm_metadata("owner_pw"))
        jsonout = config.yaml_to_dict(retout, logger=logger)
        if jsonout is None:
            logger.warning("Could not read YAML output of tpm2_getcap.")
            jsonout = {}
        for key in jsonout:
            if str(hex(key)) != self.defaults["ek_handle"]:
                logger.debug("Flushing key handle %s", hex(key))
                if self.tools_version == "3.2":
                    self.__run(["tpm2_evictcontrol", "-A", "o", "-H", hex(key), "-P", owner_pw], raiseOnError=False)
                else:
                    self.__run(["tpm2_evictcontrol", "-C", "o", "-c", hex(key), "-P", owner_pw], raiseOnError=False)
        # Make sure that all transient objects are flushed
        self.__run(["tpm2_flushcontext", "-t"], lock=False, raiseOnError=False)

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
            challenge = tpm_abstract.TPM_Utilities.random_password(32)
            challenge = challenge.encode()
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

    def activate_identity(self, keyblob: bytes) -> Optional[bytes]:
        owner_pw = cast(str, self.get_tpm_metadata("owner_pw"))
        aik_keyhandle = cast(int, self.get_tpm_metadata("aik_handle"))
        ek_keyhandle = cast(int, self.get_tpm_metadata("ek_handle"))

        assert aik_keyhandle is not None
        assert ek_keyhandle is not None

        keyblobFile = None
        secpath = None
        secfd = -1
        sesspath = None
        sesspathfd = -1
        try:
            # write out key blob
            kfd, ktemp = tempfile.mkstemp()
            with open(ktemp, "wb") as keyblobFile:
                # the below is a coroutine?
                keyblobFile.write(base64.b64decode(keyblob))

            os.close(kfd)

            # ok lets write out the key now
            secdir = secure_mount.mount()  # confirm that storage is still securely mounted

            secfd, secpath = tempfile.mkstemp(dir=secdir)
            sesspathfd, sesspath = tempfile.mkstemp(dir=secdir)

            apw = self.get_tpm_metadata("aik_pw")
            if self.tools_version == "3.2":
                command = [
                    "tpm2_activatecredential",
                    "-H",
                    hex(aik_keyhandle),
                    "-k",
                    hex(ek_keyhandle),
                    "-f",
                    keyblobFile.name,
                    "-o",
                    secpath,
                    "-P",
                    apw,
                    "-e",
                    owner_pw,
                ]
                retDict = self.__run(command, outputpaths=secpath)
            else:
                self.__run(["tpm2_startauthsession", "--policy-session", "-S", sesspath])
                self.__run(["tpm2_policysecret", "-S", sesspath, "-c", "0x4000000B", owner_pw])
                command = [
                    "tpm2_activatecredential",
                    "-c",
                    aik_keyhandle,
                    "-C",
                    hex(ek_keyhandle),
                    "-i",
                    keyblobFile.name,
                    "-o",
                    secpath,
                    "-p",
                    apw,
                    "-P",
                    f"session:{sesspath}",
                ]
                retDict = self.__run(command, outputpaths=secpath)
                self.__run(["tpm2_flushcontext", sesspath])

            # Make sure that all transient objects are flushed
            self.__run(["tpm2_flushcontext", "-t"], raiseOnError=False)

            fileout = retDict["fileouts"][secpath]
            logger.info("AIK activated.")

            key = base64.b64encode(fileout)

        except Exception as e:
            logger.error("Error decrypting AIK: %s", str(e))
            logger.exception(e)
            return None
        finally:
            if keyblobFile is not None:
                os.remove(keyblobFile.name)
            if secfd >= 0:
                os.close(secfd)
            if secpath is not None and os.path.exists(secpath):
                os.remove(secpath)
            if sesspathfd >= 0:
                os.close(sesspathfd)
            if sesspath is not None and os.path.exists(sesspath):
                os.remove(sesspath)
        return key

    def verify_ek(self, ekcert: bytes, tpm_cert_store: str) -> bool:
        """Verify that the provided EK certificate is signed by a trusted root
        :param ekcert: The Endorsement Key certificate in DER format
        :returns: True if the certificate can be verified, false otherwise
        """
        return cert_utils.verify_ek(ekcert, tpm_cert_store)

    def get_tpm_manufacturer(self, output: Optional[List[bytes]] = None) -> str:
        vendorStr = None
        retout = output

        if not retout:
            if self.tools_version == "3.2":
                retDict = self.__run(["tpm2_getcap", "-c", "properties-fixed"])
            elif self.tools_version in ["4.0", "4.2", "5.4"]:
                retDict = self.__run(["tpm2_getcap", "properties-fixed"])
            else:
                raise Exception(f"Unsupported tools version: {self.tools_version}")

            retout = retDict["retout"]
            reterr = retDict["reterr"]
            code = retDict["code"]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("get_tpm_manufacturer failed with code " + str(code) + ": " + str(reterr))

        # Clean up TPM manufacturer information (strip control characters)
        # These strings are supposed to be printable ASCII characters, but
        # some TPM manufacturers put control characters in here
        #
        # TPM manufacturer information can also contain un-escaped
        # double quotes. Making sure that un-escaped quotes are
        # replaced before attempting YAML parse.
        def quoterepl(m):
            return '"' + m.group(0)[1:-1].replace('"', '\\"') + '"'

        for i, s in enumerate(retout):
            s1 = re.sub(r'(?!".*\\".*")".*".*"', quoterepl, s.decode("utf-8"))
            retout[i] = re.sub(r"[\x01-\x1F\x7F]", "", s1).encode("utf-8")

        retyaml = config.yaml_to_dict(retout, logger=logger)
        if retyaml is None:
            raise Exception("Could not read YAML output of tpm2_getcap.")
        if "TPM2_PT_VENDOR_STRING_1" in retyaml:
            vendorStr = retyaml["TPM2_PT_VENDOR_STRING_1"]["value"]
        elif "TPM_PT_VENDOR_STRING_1" in retyaml:
            vendorStr = retyaml["TPM_PT_VENDOR_STRING_1"]["as string"].strip()
        else:
            vendorStr = ""

        return vendorStr

    def is_emulator(self) -> bool:
        return self.get_tpm_manufacturer() == "SW"

    def tpm_init(self, self_activate: bool = False, config_pw: Optional[str] = None):
        # this was called tpm_initialize.init before
        self.warn_emulator()

        self.defaults["ek_handle"] = config.get("agent", "ek_handle")

        if self.need_hw_tpm:
            # We don't know which algs the TPM supports yet
            self.supported["encrypt"] = set()
            self.supported["hash"] = set()
            self.supported["sign"] = set()

            # Grab which default algs the config requested
            defaultHash = config.get("agent", "tpm_hash_alg")
            defaultEncrypt = config.get("agent", "tpm_encryption_alg")
            defaultSign = config.get("agent", "tpm_signing_alg")

            if self.defaults["ek_handle"] == "generate":
                # Start up the TPM
                self.__startup_tpm()

            # Figure out which algorithms the TPM supports
            self.__get_tpm_algorithms()

            # Ensure TPM supports the defaults requested
            if defaultHash not in self.supported["hash"]:
                raise Exception(f"Unsupported hash algorithm specified: {str(defaultHash)}!")

            if defaultEncrypt not in self.supported["encrypt"]:
                raise Exception(f"Unsupported encryption algorithm specified: {str(defaultEncrypt)}!")

            if defaultSign not in self.supported["sign"]:
                raise Exception(f"Unsupported signing algorithm specified: {str(defaultSign)}!")

            enabled_pcrs = self.__get_pcrs()
            if not enabled_pcrs.get(str(defaultHash)):
                raise Exception(f"No PCR banks enabled for hash algorithm specified: {defaultHash}")

            self.defaults["hash"] = algorithms.Hash(defaultHash)
            self.defaults["encrypt"] = defaultEncrypt
            self.defaults["sign"] = defaultSign

        if self.defaults["ek_handle"] == "generate":
            self.__take_ownership(config_pw)
            self.__create_ek()
        else:
            self.__use_ek(self.defaults["ek_handle"], config_pw)

        self.__get_pub_ek()

        ekcert = self.read_ekcert_nvram()
        self._set_tpm_metadata("ekcert", ekcert)

        # if no AIK created, then create one
        self.__create_aik()

        return self.get_tpm_metadata("ekcert"), self.get_tpm_metadata("ek_tpm"), self.get_tpm_metadata("aik_tpm")

    # tpm_quote
    @staticmethod
    def __pcr_mask_to_list(mask: str) -> str:
        pcr_list = []
        for pcr in range(24):
            if tpm_abstract.TPM_Utilities.check_mask(mask, pcr):
                pcr_list.append(str(pcr))
        return ",".join(pcr_list)

    def create_quote(
        self,
        nonce: str,
        data: Optional[bytes] = None,
        pcrmask: str = tpm_abstract.AbstractTPM.EMPTYMASK,
        hash_alg: Optional[str] = None,
        compress: bool = False,
    ) -> str:
        if hash_alg is None:
            hash_alg = self.defaults["hash"]

        quote = ""

        with tempfile.NamedTemporaryFile() as quotepath, tempfile.NamedTemporaryFile() as sigpath, tempfile.NamedTemporaryFile() as pcrpath:
            keyhandle = cast(int, self.get_tpm_metadata("aik_handle"))
            aik_pw = self.get_tpm_metadata("aik_pw")

            assert keyhandle is not None

            if pcrmask is None:
                pcrmask = tpm_abstract.AbstractTPM.EMPTYMASK

            if data is not None:
                # add PCR 16 to pcrmask
                pcrmask = hex(int(pcrmask, 0) | (1 << config.TPM_DATA_PCR))

            pcrlist = self.__pcr_mask_to_list(pcrmask)

            with self.tpmutilLock:
                if data is not None:
                    self.__run(["tpm2_pcrreset", str(config.TPM_DATA_PCR)], lock=False)
                    hashval = self.hashdigest(data)
                    assert hashval is not None  # FIXME
                    self.extendPCR(pcrval=config.TPM_DATA_PCR, hashval=hashval, lock=False)

                nonce = bytes(nonce, encoding="utf8").hex()
                if self.tools_version == "3.2":
                    command = [
                        "tpm2_quote",
                        "-k",
                        hex(keyhandle),
                        "-L",
                        f"{str(hash_alg)}:{pcrlist}",
                        "-q",
                        nonce,
                        "-m",
                        quotepath.name,
                        "-s",
                        sigpath.name,
                        "-p",
                        pcrpath.name,
                        "-G",
                        hash_alg,
                        "-P",
                        aik_pw,
                    ]
                else:
                    command = [
                        "tpm2_quote",
                        "-c",
                        keyhandle,
                        "-l",
                        f"{str(hash_alg)}:{pcrlist}",
                        "-q",
                        nonce,
                        "-m",
                        quotepath.name,
                        "-s",
                        sigpath.name,
                        "-o",
                        pcrpath.name,
                        "-g",
                        hash_alg,
                        "-p",
                        aik_pw,
                    ]

                retDict = self.__run(command, lock=False, outputpaths=[quotepath.name, sigpath.name, pcrpath.name])
                # Make sure that all transient objects are flushed
                self.__run(["tpm2_flushcontext", "-t"], lock=False, raiseOnError=False)
                quoteraw = retDict["fileouts"][quotepath.name]
                sigraw = retDict["fileouts"][sigpath.name]
                pcrraw = retDict["fileouts"][pcrpath.name]
                if compress:
                    quoteraw = zlib.compress(quoteraw)
                    sigraw = zlib.compress(sigraw)
                    pcrraw = zlib.compress(pcrraw)
                quote_b64encode = base64.b64encode(quoteraw)
                sigraw_b64encode = base64.b64encode(sigraw)
                pcrraw_b64encode = base64.b64encode(pcrraw)
                quote = (
                    quote_b64encode.decode("utf-8")
                    + ":"
                    + sigraw_b64encode.decode("utf-8")
                    + ":"
                    + pcrraw_b64encode.decode("utf-8")
                )

        return "r" + quote

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
        aikFromRegistrar = tpm2_objects.pubkey_from_tpm2b_public(base64.b64decode(aikTpmFromRegistrar),).public_bytes(
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
        tpm_policy: Optional[Union[str, Dict]] = None,
        ima_measurement_list: Optional[str] = None,
        allowlist: Optional[Union[str, Dict[str, Any]]] = None,
        hash_alg: Optional[Hash] = None,
        ima_keyrings: Optional[ImaKeyrings] = None,
        mb_measurement_list: Optional[str] = None,
        mb_refstate: Optional[str] = None,
        compressed: bool = False,
    ) -> Failure:
        if tpm_policy is None:
            tpm_policy = {}

        if allowlist is None:
            allowlist = {}

        agent_id = agentAttestState.agent_id

        failure = Failure(Component.QUOTE_VALIDATION)
        if hash_alg is None:
            hash_alg = Hash(self.defaults["hash"])

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
            False,
            ima_measurement_list,
            allowlist,
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

    def sim_extend(self, hashval_1: str, hashval_0: Optional[str] = None, hash_alg: Optional[Hash] = None) -> str:
        # simulate extending a PCR value by performing TPM-specific extend procedure

        if hashval_0 is None:
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

    def extendPCR(self, pcrval: int, hashval: str, hash_alg: Optional[Hash] = None, lock: bool = True) -> None:
        if hash_alg is None:
            hash_alg = Hash(self.defaults["hash"]).value

        self.__run(["tpm2_pcrextend", f"{pcrval}:{str(hash_alg)}={hashval}"], lock=lock)

    def readPCR(self, pcrval: int, hash_alg: Optional[Hash] = None) -> str:
        if hash_alg is None:
            hash_alg = Hash(self.defaults["hash"])
        if self.tools_version == "3.2":
            output = config.convert(self.__run("tpm2_pcrlist")["retout"])
        else:
            output = config.convert(self.__run("tpm2_pcrread")["retout"])

        jsonout = config.yaml_to_dict(output, logger=logger)
        if jsonout is None:
            raise Exception("Could not read YAML output of tpm2_pcrread.")

        if not jsonout.get(hash_alg):
            raise Exception(f"Invalid hashing algorithm '{hash_alg}' for reading PCR number {pcrval}.")

        # alg_size = Hash_Algorithms.get_hash_size(hash_alg)/4
        alg_size = hash_alg.get_size() // 4
        return f"{jsonout[hash_alg][pcrval]:0{alg_size}x}"

    # tpm_random
    def _get_tpm_rand_block(self, size: int = 32) -> Optional[bytes]:
        # make a temp file for the output
        rand = None
        with tempfile.NamedTemporaryFile() as randpath:
            try:
                command = ["tpm2_getrandom", "-o", randpath.name, str(size)]
                retDict = self.__run(command, outputpaths=randpath.name)
                rand = retDict["fileouts"][randpath.name]
            except Exception as e:
                if not self.tpmrand_warned:
                    logger.warning("TPM randomness not available: %s", e)
                    self.tpmrand_warned = True
                return None
        return rand

    # tpm_nvram
    def write_key_nvram(self, key: bytes) -> None:
        owner_pw = cast(str, self.get_tpm_metadata("owner_pw"))

        # write out quote
        with tempfile.NamedTemporaryFile() as keyFile:
            keyFile.write(key)
            keyFile.flush()

            attrs = "ownerread|ownerwrite"
            # TODO(kaifeng) Escaping attrs is probably not required
            if self.tools_version == "3.2":
                self.__run(
                    [
                        "tpm2_nvdefine",
                        "-x",
                        "0x1500018",
                        "-a",
                        "0x40000001",
                        "-s",
                        str(config.BOOTSTRAP_KEY_SIZE),
                        "-t",
                        f'"{attrs}"',
                        "-I",
                        owner_pw,
                        "-P",
                        owner_pw,
                    ],
                    raiseOnError=False,
                )
                self.__run(
                    ["tpm2_nvwrite", "-x", "0x1500018", "-a", "0x40000001", "-P", owner_pw, keyFile.name],
                    raiseOnError=False,
                )
            else:
                self.__run(
                    [
                        "tpm2_nvdefine",
                        "0x1500018",
                        "-C",
                        "0x40000001",
                        "-s",
                        str(config.BOOTSTRAP_KEY_SIZE),
                        "-a",
                        f'"{attrs}"',
                        "-p",
                        owner_pw,
                        "-P",
                        owner_pw,
                    ],
                    raiseOnError=False,
                )
                self.__run(
                    ["tpm2_nvwrite", "0x1500018", "-C", "0x40000001", "-P", owner_pw, "-i", keyFile.name],
                    raiseOnError=False,
                )

    def read_ekcert_nvram(self) -> Optional[bytes]:
        # make a temp file for the quote
        with tempfile.NamedTemporaryFile() as nvpath:

            # Check for RSA EK cert in NVRAM (and get length)
            if self.tools_version == "3.2":
                retDict = self.__run("tpm2_nvlist", raiseOnError=False)
            else:
                retDict = self.__run("tpm2_nvreadpublic", raiseOnError=False)

            output = retDict["retout"]
            reterr = retDict["reterr"]
            code = retDict["code"]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                if self.tools_version == "3.2":
                    raise Exception("tpm2_nvlist for ekcert failed with code " + str(code) + ": " + str(reterr))
                if self.tools_version in ["4.0", "4.2", "5.4"]:
                    raise Exception("tpm2_nvreadpublic for ekcert failed with code " + str(code) + ": " + str(reterr))

            outjson = config.yaml_to_dict(output, logger=logger)

            if outjson is None or 0x1C00002 not in outjson or "size" not in outjson[0x1C00002]:
                logger.warning("No EK certificate found in TPM NVRAM")
                return None

            ekcert_size = str(outjson[0x1C00002]["size"])

            # Read the RSA EK cert from NVRAM (DER format)
            if self.tools_version == "3.2":
                retDict = self.__run(
                    ["tpm2_nvread", "-x", "0x1c00002", "-s", ekcert_size, "-f", nvpath.name, "-a", "0x01c00002"],
                    raiseOnError=False,
                    outputpaths=nvpath.name,
                )
            else:
                retDict = self.__run(
                    ["tpm2_nvread", "0x1c00002", "-s", ekcert_size, "-o", nvpath.name],
                    raiseOnError=False,
                    outputpaths=nvpath.name,
                )
            output = config.convert(retDict["retout"])
            errout = config.convert(retDict["reterr"])
            code = retDict["code"]
            ekcert = retDict["fileouts"][nvpath.name]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_nvread for ekcert failed with code " + str(code) + ": " + str(errout))

        return base64.b64encode(ekcert)

    def read_key_nvram(self) -> Optional[List[bytes]]:
        owner_pw = cast(str, self.get_tpm_metadata("owner_pw"))
        if self.tools_version == "3.2":
            retDict = self.__run(
                [
                    "tpm2_nvread",
                    "-x",
                    "0x1500018",
                    "-a",
                    "0x40000001",
                    "-s",
                    str(config.BOOTSTRAP_KEY_SIZE),
                    "-P",
                    owner_pw,
                ],
                raiseOnError=False,
            )
        else:
            retDict = self.__run(
                ["tpm2_nvread", "0x1500018", "-C", "0x40000001", "-s", str(config.BOOTSTRAP_KEY_SIZE), "-P", owner_pw],
                raiseOnError=False,
            )

        output = retDict["retout"]
        errout = config.convert(retDict["reterr"])
        code = retDict["code"]

        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            if len(errout) > 0 and "handle does not exist" in "\n".join(errout):
                logger.debug("No stored U in TPM NVRAM")
                return None
            if len(errout) > 0 and "ERROR: Failed to read NVRAM public area at index" in "\n".join(errout):
                logger.debug("No stored U in TPM NVRAM")
                return None
            if len(errout) > 0 and "the handle is not correct for the use" in "\n".join(errout):
                logger.debug("No stored U in TPM NVRAM")
                return None

            raise Exception("nv_readvalue failed with code " + str(code) + ": " + str(errout))

        if len(output) != config.BOOTSTRAP_KEY_SIZE:
            logger.debug("Invalid key length from NVRAM: %d", len(output))
            return None
        return output

    @staticmethod
    def __stringify_pcr_keys(log: dict) -> None:
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
    def __add_boot_aggregate(log: dict) -> None:
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
    def __unescape_eventlog(log: dict) -> None:
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

        def recursive_unescape(data):
            if isinstance(data, str):
                if data.startswith('"') and data.endswith('"'):
                    data = data[1:-1]
                    for orig, escaped in escaped_chars:
                        data = data.replace(escaped, orig)
                    data = data.rstrip("\0")
            elif isinstance(data, dict):
                for key, value in data.items():
                    data[key] = recursive_unescape(value)
            elif isinstance(data, list):
                for pos, item in enumerate(data):
                    data[pos] = recursive_unescape(item)
            return data

        recursive_unescape(log)

    def parse_binary_bootlog(self, log_bin: bytes) -> typing.Tuple[Failure, typing.Optional[dict]]:
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

    def _parse_mb_bootlog(self, log_b64: str) -> typing.Tuple[Failure, typing.Optional[dict]]:
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
    ) -> typing.Tuple[dict, typing.Optional[dict], dict, Failure]:
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
