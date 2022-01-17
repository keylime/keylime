'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import base64
import binascii
import hashlib
import os
import re
import sys
import tempfile
import threading
import time
import typing
import zlib
import codecs
from distutils.version import StrictVersion

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from keylime import cmd_exec
from keylime import config
from keylime import json
from keylime import keylime_logging
from keylime import secure_mount
from keylime.tpm import tpm_abstract
from keylime import tpm_ek_ca
from keylime.common import algorithms
from keylime.tpm import tpm2_objects
from keylime.failure import Failure, Component

logger = keylime_logging.init_logging('tpm')


def _get_cmd_env():
    env = os.environ.copy()
    if 'TPM2TOOLS_TCTI' not in env:
        # Don't clobber existing setting (if present)
        env['TPM2TOOLS_TCTI'] = 'device:/dev/tpmrm0'
        # env['TPM2TOOLS_TCTI'] = 'tabrmd:bus_name=com.intel.tss2.Tabrmd'
        # Other (not recommended) options are direct emulator and chardev communications:
        # env['TPM2TOOLS_TCTI'] = 'mssim:port=2321'
        # env['TPM2TOOLS_TCTI'] = 'device:/dev/tpm0'
    return env


def _stub_command(fprt, lock, cmd, outputpaths):
    # cmd is an iteratable now, change cmd to string to match old logic below
    cmd = ' '.join(cmd)
    # Use canned values for stubbing
    jsonIn = config.TPM_CANNED_VALUES
    if fprt in jsonIn:
        # The value we're looking for has been canned!
        thisTiming = jsonIn[fprt]['timing']
        thisRetout = jsonIn[fprt]['retout']
        thisCode = jsonIn[fprt]['code']
        thisFileout = jsonIn[fprt]['fileout']
        fileoutEncoded = {}

        # Decode files that are supplied (and requested)
        if outputpaths is not None and len(outputpaths) > 0:
            if len(thisFileout) == 1 and len(outputpaths) == 1:
                # fileoutEncoded[outputpaths[0]] = base64.b64decode(next(iter(thisFileout.values()))).decode("zlib")
                fileoutEncoded[outputpaths[0]] = zlib.decompress(base64.b64decode(next(iter(thisFileout.values()))))
            elif fprt == "tpm2_deluxequote":
                # quotes need 3 outputs, so we need a consistent way to match them back up when reading
                quote_msg = ""
                match = re.search(r"-m ([^\s]+)", cmd)
                if match:
                    quote_msg = match.group(1)
                    if "file://quoteMessage" in thisFileout:
                        # fileoutEncoded[quote_msg] = base64.b64decode(thisFileout["file://quoteMessage"]).decode("zlib")
                        fileoutEncoded[quote_msg] = zlib.decompress(
                            base64.b64decode(thisFileout["file://quoteMessage"]))
                quote_sig = ""
                match = re.search(r"-s ([^\s]+)", cmd)
                if match:
                    quote_sig = match.group(1)
                    if "file://quoteSignature" in thisFileout:
                        # fileoutEncoded[quote_sig] = base64.b64decode(thisFileout["file://quoteSignature"]).decode("zlib")
                        fileoutEncoded[quote_sig] = zlib.decompress(
                            base64.b64decode(thisFileout["file://quoteSignature"]))
                quote_pcr = ""
                match = re.search(r"-p ([^\s]+)", cmd)
                if match:
                    quote_pcr = match.group(1)
                    if "file://quotePCR" in thisFileout:
                        # fileoutEncoded[quote_pcr] = base64.b64decode(thisFileout["file://quotePCR"]).decode("zlib")
                        fileoutEncoded[quote_pcr] = zlib.decompress(
                            base64.b64decode(thisFileout["file://quotePCR"]))
            else:
                raise Exception("Command %s is using multiple files unexpectedly!" % fprt)

        logger.debug("TPM call '%s' was stubbed out, with a simulated delay of %f sec" % (fprt, thisTiming))
        time.sleep(thisTiming)

        # Package for return
        returnDict = {
            'retout': thisRetout,
            'reterr': [],
            'code': thisCode,
            'fileouts': fileoutEncoded,
            'timing': thisTiming,
        }
        return returnDict
    if not lock:
        # non-lock calls don't go to the TPM (just let it pass through)
        return None

    # Our command hasn't been canned!
    raise Exception("Command %s not found in canned YAML!" % fprt)


def _output_metrics(fprt, cmd, cmd_ret, outputpaths):
    # cmd is an iteratable now, change cmd to string to match old logic below
    cmd = ' '.join(cmd)
    t0 = cmd_ret['timing']['t0']
    t1 = cmd_ret['timing']['t1']
    code = cmd_ret['code']
    retout = cmd_ret['retout']
    fileouts = cmd_ret['fileouts']

    pad = ""
    if len(fprt) < 8:
        pad += "\t"
    if len(fprt) < 16:
        pad += "\t"
    if len(fprt) < 24:
        pad += "\t"

    filelen = 0
    if fileouts is not None:
        filelen = len(fileouts)

    # Print out benchmarking information for TPM (if requested)
    # print "\033[95mTIMING: %s%s\t:%f\toutlines:%d\tfilelines:%d\t%s\033[0m" % (fprt, pad, t1-t0, len(retout), filelen, cmd)
    if config.TPM_BENCHMARK_PATH is not None:
        with open(config.TPM_BENCHMARK_PATH, "ab") as f:
            f.write(
                "TIMING: %s%s\t:%f\toutlines:%d\tfilelines:%d\t%s\n" % (fprt, pad, t1 - t0, len(retout), filelen, cmd))

    # Print out YAML canned values (if requested)
    # NOTE: resulting file will be missing the surrounding braces! (must add '{' and '}' for reading)
    if config.TPM_CANNED_VALUES_PATH is not None:
        with open(config.TPM_CANNED_VALUES_PATH, "ab") as can:
            fileoutEncoded = {}

            # Process files
            if outputpaths is not None and len(outputpaths) > 0:
                if len(fileouts) == 1 and len(outputpaths) == 1:
                    # fileoutEncoded[outputpaths[0]] = base64.b64encode(iter(fileouts.values()).next().encode("zlib"))
                    fileoutEncoded[outputpaths[0]] = zlib.compress(base64.b64decode(iter(fileouts.values()).next()))
                elif fprt == "tpm2_deluxequote":
                    # quotes need 3 outputs, so we need a consistent way to match them back up when reading
                    quote_msg = ""
                    match = re.search(r"-m ([^\s]+)", cmd)
                    if match:
                        quote_msg = match.group(1)
                        if quote_msg in fileouts:
                            # fileoutEncoded["file://quoteMessage"] = base64.b64encode(fileouts[quote_msg].encode("zlib"))
                            fileoutEncoded["file://quoteMessage"] = zlib.compress(base64.b64decode(fileouts[quote_msg]))
                    quote_sig = ""
                    match = re.search(r"-s ([^\s]+)", cmd)
                    if match:
                        quote_sig = match.group(1)
                        if quote_sig in fileouts:
                            # fileoutEncoded["file://quoteSignature"] = base64.b64encode(fileouts[quote_sig].encode("zlib"))
                            fileoutEncoded["file://quoteSignature"] = zlib.compress(
                                base64.b64decode(fileouts[quote_sig]))
                    quote_pcr = ""
                    match = re.search(r"-p ([^\s]+)", cmd)
                    if match:
                        quote_pcr = match.group(1)
                        if quote_pcr in fileouts:
                            # fileoutEncoded["file://quotePCR"] = base64.b64encode(fileouts[quote_pcr].encode("zlib"))
                            fileoutEncoded["file://quotePCR"] = zlib.compress(base64.b64decode(fileouts[quote_pcr]))
                else:
                    raise Exception("Command %s is using multiple files unexpectedly!" % (fprt))

            # tpm_cexec will need to know the nonce
            nonce = ""
            match = re.search(r"-q ([\w]+)", cmd)
            if match:
                nonce = binascii.a2b_hex(match.group(1))

            jsonObj = {
                'type': fprt,
                'retout': retout,
                'fileout': fileoutEncoded,
                'cmd': cmd,
                'timing': t1 - t0,
                'code': code,
                'nonce': nonce
            }
            can.write("\"%s\": %s,\n" % (fprt, json.dumps(jsonObj, indent=4, sort_keys=True)))


class tpm(tpm_abstract.AbstractTPM):
    VERSION = 2
    tools_version = ""

    def __init__(self, need_hw_tpm=False):
        tpm_abstract.AbstractTPM.__init__(self, need_hw_tpm)

        # Shared lock to serialize access to tools
        self.tpmutilLock = threading.Lock()

        self.__get_tpm2_tools()

        # We don't know which algs the TPM supports yet
        self.supported['encrypt'] = set()
        self.supported['hash'] = set()
        self.supported['sign'] = set()

        # Grab which default algs the config requested
        defaultHash = config.get('cloud_agent', "tpm_hash_alg")
        defaultEncrypt = config.get('cloud_agent', "tpm_encryption_alg")
        defaultSign = config.get('cloud_agent', "tpm_signing_alg")

        ek_handle = config.get('cloud_agent', 'ek_handle')

        if self.need_hw_tpm:
            if ek_handle == "generate":
                # Start up the TPM
                self.__startup_tpm()

            # Figure out which algorithms the TPM supports
            self.__get_tpm_algorithms()

            # Ensure TPM supports the defaults requested
            if defaultHash not in self.supported['hash']:
                raise Exception('Unsupported hash algorithm specified: %s!' % (defaultHash))
            if defaultEncrypt not in self.supported['encrypt']:
                raise Exception('Unsupported encryption algorithm specified: %s!' % (defaultEncrypt))
            if defaultSign not in self.supported['sign']:
                raise Exception('Unsupported signing algorithm specified: %s!' % (defaultSign))
        else:
            # Assume their defaults are sane?
            pass

        self.defaults['hash'] = algorithms.Hash(defaultHash)
        self.defaults['encrypt'] = defaultEncrypt
        self.defaults['sign'] = defaultSign
        self.defaults['ek_handle'] = ek_handle

    def __get_tpm2_tools(self):
        retDict = self.__run(["tpm2_startup", "--version"])

        code = retDict['code']
        output = ''.join(config.convert(retDict['retout']))
        errout = ''.join(config.convert(retDict['reterr']))
        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            raise Exception("Error establishing tpm2-tools version using TPM2_Startup: %s" + str(code) + ": " + str(errout))

        # Extract the `version="x.x.x"` from tools
        version_str = re.search(r'version="([^"]+)"', output).group(1)
        # Extract the full semver release number.
        self.tools_version = version_str.split("-")

        if StrictVersion(self.tools_version[0]) >= StrictVersion("4.2"):
            logger.info("TPM2-TOOLS Version: %s" % self.tools_version[0])
            self.tools_version = "4.2"
        elif StrictVersion(self.tools_version[0]) >= StrictVersion("4.0.0"):
            logger.info("TPM2-TOOLS Version: %s" % self.tools_version[0])
            self.tools_version = "4.0"
        elif StrictVersion(self.tools_version[0]) >= StrictVersion("3.2.0"):
            logger.info("TPM2-TOOLS Version: %s" % self.tools_version[0])
            self.tools_version = "3.2"
        else:
            logger.error("TPM2-TOOLS Version %s is not supported." % self.tools_version[0])
            sys.exit()

    def __get_tpm_algorithms(self):
        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_getcap", "-c", "algorithms"])
        elif self.tools_version in ["4.0", "4.2"]:
            retDict = self.__run(["tpm2_getcap", "algorithms"])

        output = config.convert(retDict['retout'])
        errout = config.convert(retDict['reterr'])
        code = retDict['code']

        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            raise Exception("get_tpm_algorithms failed with code " + str(code) + ": " + str(errout))

        if self.tools_version == "3.2":
            # output, human-readable -> json
            output = "".join(output)
            output = re.sub(r'TPMA_ALGORITHM for ALG_ID: 0x[0-9a-f]+\s+-\s+([a-z0-9_]+)', r'\1:', output)
            output = output.replace("set", "1")
            output = output.replace("clear", "0")
            output = [output]

        retyaml = config.yaml_to_dict(output, logger=logger)
        if retyaml is None:
            logger.warning("Could not read YAML output of tpm2_getcap.")
            return
        for algorithm, details in retyaml.items():
            if details["asymmetric"] == 1 and details["object"] == 1 and algorithms.Encrypt.is_recognized(algorithm):
                self.supported['encrypt'].add(algorithm)
            elif details["hash"] == 1 and algorithms.Hash.is_recognized(algorithm):
                self.supported['hash'].add(algorithm)
            elif details["asymmetric"] == 1 and details["signing"] == 1 and algorithms.Sign.is_recognized(algorithm):
                self.supported['sign'].add(algorithm)

    # tpm_exec
    @staticmethod
    def __fingerprint(cmd):
        # Creates a unique-enough ID from the given command
        # The command should be an iterable
        fprt = cmd[0]
        if fprt == 'tpm2_nvread':
            if '0x1c00002' in cmd:  # read_ekcert_nvram
                fprt += '-ekcert'
            else:  # read_key_nvram
                fprt += '-key'
        elif fprt == "tpm2_getcap":
            if 'handles-persistent' in cmd:
                fprt += '-handles'
            elif 'properties-fixed' in cmd:
                fprt += '-props'
        else:
            # other commands are already unique
            pass
        return fprt

    def run(self, cmd):
        return self.__run(cmd, lock=False)

    def __run(self, cmd, expectedcode=tpm_abstract.AbstractTPM.EXIT_SUCESS, raiseOnError=True, lock=True, outputpaths=None):
        env = _get_cmd_env()

        # Convert single outputpath to list
        if isinstance(outputpaths, str):
            outputpaths = [outputpaths]

        # Handle stubbing the TPM out
        fprt = tpm.__fingerprint(cmd)
        if config.STUB_TPM and config.TPM_CANNED_VALUES is not None:
            stub = _stub_command(fprt, lock, cmd, outputpaths)
            if stub:
                return stub

        numtries = 0
        while True:
            if lock:
                with self.tpmutilLock:
                    retDict = cmd_exec.run(cmd=cmd, expectedcode=expectedcode,
                                           raiseOnError=False,
                                           outputpaths=outputpaths, env=env)
            else:
                retDict = cmd_exec.run(cmd=cmd, expectedcode=expectedcode,
                                       raiseOnError=False,
                                       outputpaths=outputpaths, env=env)
            code = retDict['code']
            retout = retDict['retout']
            reterr = retDict['reterr']

            # keep trying to get quote if a PCR race condition occurred in deluxe quote
            if fprt == "tpm2_quote" and cmd_exec.list_contains_substring(reterr, "Error validating calculated PCR composite with quote"):
                numtries += 1
                maxr = config.getint('cloud_agent', 'max_retries')
                if numtries >= maxr:
                    logger.error("Agent did not return proper quote due to PCR race condition.")
                    break
                retry = config.getfloat('cloud_agent', 'retry_interval')
                logger.info("Failed to get quote %d/%d times, trying again in %f seconds..." % (numtries, maxr, retry))
                time.sleep(retry)
                continue

            break

        # Don't bother continuing if TPM call failed and we're raising on error
        if code != expectedcode and raiseOnError:
            raise Exception("Command: %s returned %d, expected %d, output %s, stderr %s" % (cmd, code, expectedcode, retout, reterr))

        # Metric output
        if lock or self.tpmutilLock.locked():
            _output_metrics(fprt, cmd, retDict, outputpaths)

        return retDict

    # tpm_initialize
    def __startup_tpm(self):
        retDict = self.__run(['tpm2_startup', '-c'])
        errout = config.convert(retDict['reterr'])
        code = retDict['code']
        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            raise Exception("Error initializing emulated TPM with TPM2_Startup: %s" + str(code) + ": " + str(errout))

    def __create_ek(self, asym_alg=None):
        # this function is intended to be idempotent
        if asym_alg is None:
            asym_alg = self.defaults['encrypt']

        current_handle = self.get_tpm_metadata("ek_handle")
        owner_pw = self.get_tpm_metadata("owner_pw")

        # clear out old handle before starting again (give idempotence)
        if current_handle is not None and owner_pw is not None:
            logger.info("Flushing old ek handle: %s" % hex(current_handle))
            if self.tools_version == "3.2":
                retDict = self.__run(["tpm2_getcap", "-c", "handles-persistent"],
                                     raiseOnError=False)
            elif self.tools_version in ["4.0", "4.2"]:
                retDict = self.__run(["tpm2_getcap", "handles-persistent"],
                                     raiseOnError=False)
            output = retDict['retout']
            reterr = retDict['reterr']
            code = retDict['code']

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_getcap failed with code " + str(code) + ": " + str(reterr))

            outjson = config.yaml_to_dict(output, logger=logger)
            if outjson is not None and hex(current_handle) in outjson:
                if self.tools_version == "3.2":
                    cmd = ["tpm2_evictcontrol", "-A", "o", "-H",
                           hex(current_handle), "-P", owner_pw]
                    retDict = self.__run(cmd, raiseOnError=False)
                elif self.tools_version in ["4.0", "4.2"]:
                    cmd = ["tpm2_evictcontrol", "-C", "o", "-c",
                           hex(current_handle), "-P", owner_pw]
                    retDict = self.__run(cmd, raiseOnError=False)
                output = retDict['retout']
                reterr = retDict['reterr']
                code = retDict['code']

                if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                    logger.info("Failed to flush old ek handle: %s.  Code %s" % (hex(current_handle), str(code) + ": " + str(reterr)))

                self._set_tpm_metadata('ek_handle', None)
                self._set_tpm_metadata('ek_tpm', None)
                self._set_tpm_metadata('ek_pw', None)

        # make sure an ownership pw is set
        if owner_pw is None:
            owner_pw = tpm_abstract.TPM_Utilities.random_password(20)
            self._set_tpm_metadata('owner_pw', owner_pw)
        ek_pw = tpm_abstract.TPM_Utilities.random_password(20)

        # create a new ek
        with tempfile.NamedTemporaryFile() as tmppath:
            # TODO(kaifeng) Missing else here for other versions
            if self.tools_version == "3.2":
                command = ["tpm2_getpubek", "-H", "0x81010007", "-g", asym_alg, "-f", tmppath.name, "-P", ek_pw, "-o", owner_pw, "-e", owner_pw]
            elif self.tools_version == "4.0":
                command = ["tpm2_createek", "-c", "-", "-G", asym_alg, "-u", tmppath.name, "-p", ek_pw, "-w", owner_pw, "-P", owner_pw]
            elif self.tools_version == "4.2":
                command = ["tpm2_createek", "-c", "-", "-G", asym_alg, "-u", tmppath.name, "-w", owner_pw, "-P", owner_pw]

            retDict = self.__run(command, raiseOnError=False, outputpaths=tmppath.name)
            output = retDict['retout']
            reterr = retDict['reterr']
            code = retDict['code']
            ek_tpm = retDict['fileouts'][tmppath.name]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("createek failed with code " + str(code) + ": " + str(reterr))

            if self.tools_version == "3.2":
                handle = int(0x81010007)
            elif self.tools_version in ["4.0", "4.2"]:
                handle = None
                retyaml = config.yaml_to_dict(output, logger=logger)
                if retyaml is None:
                    raise Exception("Could not read YAML output of tpm2_createek.")
                if "persistent-handle" in retyaml:
                    handle = retyaml["persistent-handle"]

            self._set_tpm_metadata('ek_handle', handle)
            self._set_tpm_metadata('ek_pw', ek_pw)
            self._set_tpm_metadata('ek_tpm', base64.b64encode(ek_tpm))
            self._set_tpm_metadata('ek_alg', asym_alg)

    def __use_ek(self, ek_handle, config_pw):
        ek_handle = int(ek_handle, 16)
        logger.info("Using an already created ek with handle: %s" % hex(ek_handle))

        self._set_tpm_metadata('owner_pw', config_pw)

        with tempfile.NamedTemporaryFile() as tmppath:
            if self.tools_version == "3.2":
                cmd = ["tpm2_readpublic", "-H", hex(ek_handle),
                       "-o", tmppath.name, "-f", "tss"]
                retDict = self.__run(cmd, raiseOnError=False, outputpaths=tmppath.name)
            elif self.tools_version in ["4.0", "4.2"]:
                cmd = ["tpm2_readpublic", "-c", hex(ek_handle),
                       "-o", tmppath.name, "-f", "tss"]
                retDict = self.__run(cmd, raiseOnError=False, outputpaths=tmppath.name)

            reterr = retDict['reterr']
            code = retDict['code']
            ek_tpm = retDict['fileouts'][tmppath.name]
            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_readpublic failed with code " + str(code) + ": " + str(reterr))
            self._set_tpm_metadata('ek_tpm', base64.b64encode(ek_tpm))

        self._set_tpm_metadata('ek_handle', int(ek_handle))

    def __take_ownership(self, config_pw):
        # if no ownerpassword
        if config_pw == 'generate':
            logger.info("Generating random TPM owner password")
            owner_pw = tpm_abstract.TPM_Utilities.random_password(20)
        else:
            logger.info("Taking ownership with config provided TPM owner password")
            owner_pw = config_pw

        logger.debug("Removing all saved sessions from TPM")
        retDict = self.__run(["tpm2_flushcontext", "-s"], raiseOnError=False)

        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_takeownership", "-c"], raiseOnError=False)
            retDict = self.__run(["tpm2_takeownership", "-o", owner_pw, "-e", owner_pw],
                                 raiseOnError=False)
        elif self.tools_version in ["4.0", "4.2"]:
            retDict = self.__run(["tpm2_changeauth", "-c", "o", owner_pw],
                                 raiseOnError=False)
            retDict = self.__run(["tpm2_changeauth", "-c", "e", owner_pw],
                                 raiseOnError=False)

        code = retDict['code']
        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            # if we fail, see if already owned with this pw
            if self.tools_version == "3.2":
                retDict = self.__run(["tpm2_takeownership", "-o", owner_pw,
                                      "-e", owner_pw, "-O", owner_pw, "-E", owner_pw],
                                     raiseOnError=False)
            elif self.tools_version in ["4.0", "4.2"]:
                retDict = self.__run(["tpm2_changeauth", "-c", "o", "-p", owner_pw, owner_pw],
                                     raiseOnError=False)
                retDict = self.__run(["tpm2_changeauth", "-c", "e", "-p", owner_pw, owner_pw],
                                     raiseOnError=False)

            reterr = retDict['reterr']
            code = retDict['code']
            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                # ut-oh, already owned but not with provided pw!
                raise Exception("Owner password unknown, TPM reset required. Code %s" + str(code) + ": " + str(reterr))

        self._set_tpm_metadata('owner_pw', owner_pw)
        logger.info("TPM Owner password confirmed: %s" % owner_pw)

    def __get_pub_ek(self):  # assumes that owner_pw is correct at this point
        handle = self.get_tpm_metadata('ek_handle')
        if handle is None:
            raise Exception("create_ek has not been run yet?")
        # make a temp file for the output
        with tempfile.NamedTemporaryFile() as tmppath:
            # generates pubek.pem
            if self.tools_version == "3.2":
                cmd = ["tpm2_readpublic", "-H", hex(handle), "-o", tmppath.name]
                retDict = self.__run(cmd, raiseOnError=False, outputpaths=tmppath.name)
            elif self.tools_version in ["4.0", "4.2"]:
                cmd = ["tpm2_readpublic", "-c", hex(handle), "-o", tmppath.name]
                retDict = self.__run(cmd, raiseOnError=False, outputpaths=tmppath.name)

            reterr = retDict['reterr']
            code = retDict['code']
            ek = retDict['fileouts'][tmppath.name]
            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_readpublic failed with code " + str(code) + ": " + str(reterr))

        self._set_tpm_metadata('ek_tpm', base64.b64encode(ek))

    def __create_aik(self, asym_alg=None, hash_alg=None, sign_alg=None):
        if hash_alg is None:
            hash_alg = self.defaults['hash']
        if asym_alg is None:
            asym_alg = self.defaults['encrypt']
        if sign_alg is None:
            sign_alg = self.defaults['sign']

        owner_pw = self.get_tpm_metadata('owner_pw')

        # clear out old handle before starting again (give idempotence)
        if self.get_tpm_metadata('aik_handle') is not None:
            aik_handle = self.get_tpm_metadata('aik_handle')
            if self.tools_version == "3.2":
                logger.info("Flushing old ak handle: %s" % hex(aik_handle))
                retDict = self.__run(["tpm2_getcap", "-c", "handles-persistent"],
                                     raiseOnError=False)
            elif self.tools_version in ["4.0", "4.2"]:
                logger.info("Flushing old ak handle: %s" % aik_handle)
                retDict = self.__run(["tpm2_getcap", "handles-persistent"],
                                     raiseOnError=False)
            output = config.convert(retDict['retout'])
            errout = config.convert(retDict['reterr'])
            code = retDict['code']

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
            elif self.tools_version in ["4.0", "4.2"]:
                evict_it = os.path.exists(aik_handle)
            if evict_it:
                if self.tools_version == "3.2":
                    cmd = ["tpm2_evictcontrol", "-A", "o", "-H", hex(aik_handle), "-P", owner_pw]
                    retDict = self.__run(cmd, raiseOnError=False)
                elif self.tools_version in ["4.0", "4.2"]:
                    cmd = ["tpm2_evictcontrol", "-C", "o", "-c", aik_handle, "-P", owner_pw]
                    retDict = self.__run(cmd, raiseOnError=False)
                    os.remove(aik_handle)

                output = retDict['retout']
                reterr = retDict['reterr']
                code = retDict['code']

                if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                    if self.tools_version == "3.2":
                        logger.info("Failed to flush old ak handle: %s.  Code %s" % (hex(aik_handle), str(code) + ": " + str(reterr)))
                    elif self.tools_version in ["4.0", "4.2"]:
                        logger.info("Failed to flush old ak handle: %s.  Code %s" % (aik_handle, str(code) + ": " + str(reterr)))

                self._set_tpm_metadata('aik_pw', None)
                self._set_tpm_metadata('aik_tpm', None)
                self._set_tpm_metadata('aik_handle', None)

        logger.debug("Creating a new AIK identity")

        # We need an ek handle to make an aik
        ek_handle = self.get_tpm_metadata("ek_handle")
        if ek_handle is None:
            raise Exception("Failed to create AIK, since EK has not yet been created!")

        aik_pw = tpm_abstract.TPM_Utilities.random_password(20)
        # make a temp file for the output
        with tempfile.NamedTemporaryFile() as akpubfile:
            secpath = ""
            if self.tools_version in ["4.0", "4.2"]:
                # ok lets write out the key now
                secdir = secure_mount.mount()  # confirm that storage is still securely mounted
                secfd, secpath = tempfile.mkstemp(dir=secdir)

            if self.tools_version == "3.2":
                command = ["tpm2_getpubak", "-E", hex(ek_handle), "-k", "0x81010008",
                           "-g", asym_alg, "-D", hash_alg, "-s", sign_alg,
                           "-f", akpubfile.name, "-e", owner_pw, "-P", aik_pw,
                           "-o", owner_pw]
            elif self.tools_version in ["4.0", "4.2"]:
                command = ["tpm2_createak", "-C", hex(ek_handle), "-c", secpath,
                           "-G", asym_alg, "-g", hash_alg, "-s", sign_alg,
                           "-u", akpubfile.name, "-p", aik_pw, "-P", owner_pw]
            retDict = self.__run(command, outputpaths=akpubfile.name)
            if secfd >= 0:
                os.close(secfd)
            retout = retDict['retout']
            reterr = retDict['reterr']
            code = retDict['code']

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_createak failed with code " + str(code) + ": " + str(reterr))

            jsonout = config.yaml_to_dict(retout, logger=logger)
            if jsonout is None:
                raise Exception("unable to parse YAML output of tpm2_createak. Is your tpm2-tools installation up to date?")
            aik_tpm = retDict['fileouts'][akpubfile.name]
            if aik_tpm == "":
                raise Exception("unable to read public aik from create identity.  Is your tpm2-tools installation up to date?")
            self._set_tpm_metadata('aik_tpm', base64.b64encode(aik_tpm))

        if self.tools_version == "3.2":
            if 'loaded-key' not in jsonout or 'name' not in jsonout['loaded-key']:
                raise Exception("tpm2_createak failed to create aik: return " + str(reterr))

            handle = int(0x81010008)

            # get and persist the pem (not returned by tpm2_getpubak)
            self._set_tpm_metadata('aik_handle', handle)
        elif self.tools_version in ["4.0", "4.2"]:
            if 'loaded-key' not in jsonout:
                raise Exception("tpm2_createak failed to create aik: return " + str(reterr))

            handle = secpath

            # persist the pem
            self._set_tpm_metadata('aik_handle', handle)

        # persist common results
        self._set_tpm_metadata('aik_pw', aik_pw)

    def flush_keys(self):
        logger.debug("Flushing keys from TPM...")
        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_getcap", "-c", "handles-persistent"])
        elif self.tools_version in ["4.0", "4.2"]:
            retDict = self.__run(["tpm2_getcap", "handles-persistent"])
        # retout = retDict['retout']
        retout = config.convert(retDict['retout'])
        errout = config.convert(retDict['reterr'])
        code = retDict['code']

        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            logger.debug("tpm2_getcap failed with code " + str(code) + ": " + str(errout))

        if self.tools_version == "3.2":
            # output, human-readable -> json
            retout = "".join(retout)
            retout = retout.replace("0x", " - 0x")
            retout = [retout]

        owner_pw = self.get_tpm_metadata("owner_pw")
        jsonout = config.yaml_to_dict(retout, logger=logger)
        if jsonout is None:
            logger.warning("Could not read YAML output of tpm2_getcap.")
            jsonout = {}
        for key in jsonout:
            if str(hex(key)) != self.defaults['ek_handle']:
                logger.debug("Flushing key handle %s" % hex(key))
                if self.tools_version == "3.2":
                    self.__run(["tpm2_evictcontrol", "-A", "o", "-H", hex(key), "-P", owner_pw],
                               raiseOnError=False)
                elif self.tools_version in ["4.0", "4.2"]:
                    self.__run(["tpm2_evictcontrol", "-C", "o", "-c", hex(key), "-P", owner_pw],
                               raiseOnError=False)

    def encryptAIK(self, uuid, ek_tpm: bytes, aik_tpm: bytes):

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
            ekFile = open(etemp, "wb")
            ekFile.write(ek_tpm)
            ekFile.close()

            # write out the challenge
            challenge = tpm_abstract.TPM_Utilities.random_password(32)
            challenge = challenge.encode()
            keyfd, keypath = tempfile.mkstemp()
            challengeFile = open(keypath, "wb")
            challengeFile.write(challenge)
            challengeFile.close()

            # create temp file for the blob
            blobfd, blobpath = tempfile.mkstemp()
            command = ["tpm2_makecredential", "-T", "none", "-e", ekFile.name,
                       "-s", challengeFile.name, "-n", aik_name, "-o", blobpath]
            self.__run(command, lock=False)

            logger.info("Encrypting AIK for UUID %s" % uuid)

            # read in the blob
            f = open(blobpath, "rb")
            keyblob = base64.b64encode(f.read())
            f.close()

            # read in the aes key
            key = base64.b64encode(challenge)

        except Exception as e:
            logger.error("Error encrypting AIK: " + str(e))
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

    def activate_identity(self, keyblob):
        owner_pw = self.get_tpm_metadata('owner_pw')
        aik_keyhandle = self.get_tpm_metadata('aik_handle')
        ek_keyhandle = self.get_tpm_metadata('ek_handle')

        keyblobFile = None
        secpath = None
        secfd = -1
        sesspath = None
        sesspathfd = -1
        try:
            # write out key blob
            kfd, ktemp = tempfile.mkstemp()
            keyblobFile = open(ktemp, "wb")
            # the below is a coroutine?
            keyblobFile.write(base64.b64decode(keyblob))

            keyblobFile.close()
            os.close(kfd)

            # ok lets write out the key now
            secdir = secure_mount.mount()  # confirm that storage is still securely mounted

            secfd, secpath = tempfile.mkstemp(dir=secdir)
            sesspathfd, sesspath = tempfile.mkstemp(dir=secdir)

            apw = self.get_tpm_metadata('aik_pw')
            if self.tools_version == "3.2":
                command = ["tpm2_activatecredential", "-H", hex(aik_keyhandle),
                           "-k", hex(ek_keyhandle), "-f", keyblobFile.name,
                           "-o", secpath, "-P", apw, "-e", owner_pw]
                retDict = self.__run(command, outputpaths=secpath)
            elif self.tools_version in ["4.0", "4.2"]:
                self.__run(["tpm2_startauthsession", "--policy-session", "-S", sesspath])
                self.__run(["tpm2_policysecret", "-S", sesspath, "-c", "0x4000000B", owner_pw])
                command = ["tpm2_activatecredential", "-c", aik_keyhandle, "-C", hex(ek_keyhandle),
                           "-i", keyblobFile.name, "-o", secpath, "-p", apw,
                           "-P", "session:%s" % sesspath]
                retDict = self.__run(command, outputpaths=secpath)
                self.__run(["tpm2_flushcontext", sesspath])

            fileout = retDict['fileouts'][secpath]
            logger.info("AIK activated.")

            key = base64.b64encode(fileout)

        except Exception as e:
            logger.error("Error decrypting AIK: " + str(e))
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

    def verify_ek(self, ekcert):
        """Verify that the provided EK certificate is signed by a trusted root
        :param ekcert: The Endorsement Key certificate in DER format
        :returns: True if the certificate can be verified, false otherwise
        """
        # openssl x509 -inform der -in certificate.cer -out certificate.pem
        try:
            ek509 = x509.load_der_x509_certificate(
                data=ekcert,
                backend=default_backend(),
            )

            trusted_certs = tpm_ek_ca.cert_loader()
            for cert in trusted_certs:
                signcert = x509.load_pem_x509_certificate(
                    data=cert.encode(),
                    backend=default_backend(),
                )

                if ek509.issuer.rfc4514_string() != signcert.subject.rfc4514_string():
                    continue

                try:
                    signcert.public_key().verify(
                        ek509.signature,
                        ek509.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        ek509.signature_hash_algorithm,
                    )
                except crypto_exceptions.InvalidSignature:
                    continue

                logger.debug("EK cert matched cert: %s" % cert)
                return True
        except Exception as e:
            # Log the exception so we don't lose the raw message
            logger.exception(e)
            raise Exception("Error processing ek/ekcert. Does this TPM have a valid EK?").with_traceback(sys.exc_info()[2])

        logger.error("No Root CA matched EK Certificate")
        return False

    def get_tpm_manufacturer(self):
        vendorStr = None
        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_getcap", "-c", "properties-fixed"])
        elif self.tools_version in ["4.0", "4.2"]:
            retDict = self.__run(["tpm2_getcap", "properties-fixed"])
        output = retDict['retout']
        reterr = retDict['reterr']
        code = retDict['code']

        if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
            raise Exception("get_tpm_manufacturer failed with code " + str(code) + ": " + str(reterr))

        # Clean up TPM manufacturer information (strip control characters)
        # These strings are supposed to be printable ASCII characters, but
        # some TPM manufacturers put control characters in here
        for i, s in enumerate(output):
            output[i] = re.sub(r"[\x01-\x1F\x7F]", "", s.decode('utf-8')).encode('utf-8')

        retyaml = config.yaml_to_dict(output, logger=logger)
        if retyaml is None:
            raise Exception("Could not read YAML output of tpm2_getcap.")
        if "TPM2_PT_VENDOR_STRING_1" in retyaml:
            vendorStr = retyaml["TPM2_PT_VENDOR_STRING_1"]["value"]
        elif "TPM_PT_VENDOR_STRING_1" in retyaml:
            vendorStr = retyaml["TPM_PT_VENDOR_STRING_1"]["as string"].strip()

        return vendorStr

    def is_emulator(self):
        return self.get_tpm_manufacturer() == 'SW'

    def is_vtpm(self):
        return False

    def tpm_init(self, self_activate=False, config_pw=None):
        # this was called tpm_initialize.init before
        self.warn_emulator()

        if self.defaults['ek_handle'] == "generate":
            self.__take_ownership(config_pw)
            self.__create_ek()
        else:
            self.__use_ek(self.defaults['ek_handle'], config_pw)

        self.__get_pub_ek()

        ekcert = self.read_ekcert_nvram()
        self._set_tpm_metadata('ekcert', ekcert)

        # if no AIK created, then create one
        self.__create_aik()

        return self.get_tpm_metadata('ekcert'), self.get_tpm_metadata('ek_tpm'), self.get_tpm_metadata('aik_tpm')

    # tpm_quote
    @staticmethod
    def __pcr_mask_to_list(mask):
        pcr_list = []
        for pcr in range(24):
            if tpm_abstract.TPM_Utilities.check_mask(mask, pcr):
                pcr_list.append(str(pcr))
        return ",".join(pcr_list)

    def create_quote(self, nonce, data=None, pcrmask=tpm_abstract.AbstractTPM.EMPTYMASK, hash_alg=None):
        if hash_alg is None:
            hash_alg = self.defaults['hash']

        quote = ""

        with tempfile.NamedTemporaryFile() as quotepath, \
                tempfile.NamedTemporaryFile() as sigpath, \
                tempfile.NamedTemporaryFile() as pcrpath:
            keyhandle = self.get_tpm_metadata('aik_handle')
            aik_pw = self.get_tpm_metadata('aik_pw')

            if pcrmask is None:
                pcrmask = tpm_abstract.AbstractTPM.EMPTYMASK

            if data is not None:
                # add PCR 16 to pcrmask
                pcrmask = "0x%X" % (int(pcrmask, 0) + (1 << config.TPM_DATA_PCR))

            pcrlist = self.__pcr_mask_to_list(pcrmask)

            with self.tpmutilLock:
                if data is not None:
                    self.__run(["tpm2_pcrreset", str(config.TPM_DATA_PCR)], lock=False)
                    self.extendPCR(pcrval=config.TPM_DATA_PCR, hashval=self.hashdigest(data), lock=False)

                nonce = bytes(nonce, encoding="utf8").hex()
                if self.tools_version == "3.2":
                    command = ["tpm2_quote", "-k", hex(keyhandle), "-L", "%s:%s" % (hash_alg, pcrlist), "-q", nonce, "-m", quotepath.name, "-s", sigpath.name, "-p", pcrpath.name, "-G", hash_alg, "-P", aik_pw]
                elif self.tools_version in ["4.0", "4.2"]:
                    command = ["tpm2_quote", "-c", keyhandle, "-l", "%s:%s" % (hash_alg, pcrlist), "-q", nonce, "-m", quotepath.name, "-s", sigpath.name, "-o", pcrpath.name, "-g", hash_alg, "-p", aik_pw]
                retDict = self.__run(command, lock=False, outputpaths=[quotepath.name, sigpath.name, pcrpath.name])
                quoteraw = retDict['fileouts'][quotepath.name]
                quote_b64encode = base64.b64encode(zlib.compress(quoteraw))
                sigraw = retDict['fileouts'][sigpath.name]
                sigraw_b64encode = base64.b64encode(zlib.compress(sigraw))
                pcrraw = retDict['fileouts'][pcrpath.name]
                pcrraw_b64encode = base64.b64encode(zlib.compress(pcrraw))
                quote = quote_b64encode.decode('utf-8') + ":" + sigraw_b64encode.decode('utf-8') + ":" + pcrraw_b64encode.decode('utf-8')

        return 'r' + quote

    def __tpm2_checkquote(self, pubaik, nonce, quoteFile, sigFile, pcrFile, hash_alg):
        if config.STUB_TPM and config.TPM_CANNED_VALUES is not None:
            jsonIn = config.TPM_CANNED_VALUES
            if 'tpm2_deluxequote' in jsonIn and 'nonce' in jsonIn['tpm2_deluxequote']:
                # YAML unicode-ifies strings, and C calls require byte strings (str)
                nonce = str(jsonIn['tpm2_deluxequote']['nonce'])
            else:
                raise Exception("Could not get quote nonce from canned JSON!")

        nonce = bytes(nonce, encoding="utf8").hex()
        if self.tools_version == "3.2":
            command = ["tpm2_checkquote", "-c", pubaik, "-m", quoteFile, "-s", sigFile, "-p", pcrFile, "-G", hash_alg, "-q", nonce]
        elif self.tools_version in ["4.0", "4.2"]:
            command = ["tpm2_checkquote", "-u", pubaik, "-m", quoteFile, "-s", sigFile, "-f", pcrFile, "-g", hash_alg, "-q", nonce]
        retDict = self.__run(command, lock=False)
        return retDict

    def _tpm2_checkquote(self, aikTpmFromRegistrar, quote, nonce, hash_alg):
        """Write the files from data returned from tpm2_quote for running tpm2_checkquote
        :param aikTpmFromRegistrar: AIK used to generate the quote and is needed for verifying it now.
        :param quote: quote data in the format 'r<b64-compressed-quoteblob>:<b64-compressed-sigblob>:<b64-compressed-pcrblob>
        :param nonce: nonce that was used to create the quote
        :param hash_alg: the hash algorithm that was used
        :returns: Returns the 'retout' from running tpm2_checkquote and True in case of success, None and False in case of error.
        This function throws an Exception on bad input.
        """
        aikFromRegistrar = tpm2_objects.pubkey_from_tpm2b_public(
            base64.b64decode(aikTpmFromRegistrar),
            ).public_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        if quote[0] != 'r':
            raise Exception("Invalid quote type %s" % quote[0])
        quote = quote[1:]

        quote_tokens = quote.split(":")
        if len(quote_tokens) < 3:
            raise Exception("Quote is not compound! %s" % quote)

        quoteblob = zlib.decompress(base64.b64decode(quote_tokens[0]))
        sigblob = zlib.decompress(base64.b64decode(quote_tokens[1]))
        pcrblob = zlib.decompress(base64.b64decode(quote_tokens[2]))

        qfd = sfd = pfd = afd = -1
        quoteFile = None
        aikFile = None
        sigFile = None
        pcrFile = None

        try:
            # write out quote
            qfd, qtemp = tempfile.mkstemp()
            quoteFile = open(qtemp, "wb")
            quoteFile.write(quoteblob)
            quoteFile.close()

            # write out sig
            sfd, stemp = tempfile.mkstemp()
            sigFile = open(stemp, "wb")
            sigFile.write(sigblob)
            sigFile.close()

            # write out pcr
            pfd, ptemp = tempfile.mkstemp()
            pcrFile = open(ptemp, "wb")
            pcrFile.write(pcrblob)
            pcrFile.close()

            afd, atemp = tempfile.mkstemp()
            aikFile = open(atemp, "wb")
            aikFile.write(aikFromRegistrar)
            aikFile.close()

            retDict = self.__tpm2_checkquote(aikFile.name, nonce, quoteFile.name, sigFile.name, pcrFile.name, hash_alg)
            retout = retDict['retout']
            reterr = retDict['reterr']
            code = retDict['code']
        except Exception as e:
            logger.error("Error verifying quote: " + str(e))
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
            logger.error("Failed to validate signature, output: %s" % reterr)
            return None, False

        return retout, True

    def check_quote(self, agentAttestState, nonce, data, quote, aikTpmFromRegistrar, tpm_policy={},
                    ima_measurement_list=None, allowlist={}, hash_alg=None, ima_keyrings=None,
                    mb_measurement_list=None, mb_refstate=None) -> Failure:
        failure = Failure(Component.QUOTE_VALIDATION)
        if hash_alg is None:
            hash_alg = self.defaults['hash']

        retout, success = self._tpm2_checkquote(aikTpmFromRegistrar, quote, nonce, hash_alg)
        if not success:
            # If the quote validation fails we will skip all other steps therefore this failure is irrecoverable.
            failure.add_event("quote_validation", {"message": "Quote validation using tpm2-tools", "data": retout}, False)
            return failure

        pcrs = []
        jsonout = config.yaml_to_dict(retout, logger=logger)
        if jsonout is None:
            failure.add_event("quote_validation", {"message": "YAML parsing failed for quote validation using tpm2-tools.",
                                                    "data": retout}, False)
            return failure
        if "pcrs" in jsonout:
            if hash_alg in jsonout["pcrs"]:
                alg_size = hash_alg.get_size() // 4
                for pcrval, hashval in jsonout["pcrs"][hash_alg].items():
                    pcrs.append("PCR " + str(pcrval) + " " + '{0:0{1}x}'.format(hashval, alg_size))

        if len(pcrs) == 0:
            pcrs = None

        return self.check_pcrs(agentAttestState, tpm_policy, pcrs, data, False, ima_measurement_list, allowlist,
                               ima_keyrings, mb_measurement_list, mb_refstate, hash_alg)

    def sim_extend(self, hashval_1, hashval_0=None, hash_alg=None):
        # simulate extending a PCR value by performing TPM-specific extend procedure

        if hashval_0 is None:
            hashval_0 = self.START_HASH(hash_alg)

        # compute expected value  H(0|H(data))
        extendedval = self.hashdigest(codecs.decode(hashval_0, 'hex_codec') +
                                      codecs.decode(self.hashdigest(hashval_1.encode('utf-8'), hash_alg), 'hex_codec'),
                                      hash_alg).lower()
        return extendedval

    def extendPCR(self, pcrval, hashval, hash_alg=None, lock=True):
        if hash_alg is None:
            hash_alg = self.defaults['hash'].value

        self.__run(["tpm2_pcrextend", "%d:%s=%s" % (pcrval, hash_alg, hashval)], lock=lock)

    def readPCR(self, pcrval, hash_alg=None):
        if hash_alg is None:
            hash_alg = self.defaults['hash']
        if self.tools_version == "3.2":
            output = config.convert(self.__run("tpm2_pcrlist")['retout'])
        elif self.tools_version in ["4.0", "4.2"]:
            output = config.convert(self.__run("tpm2_pcrread")['retout'])

        jsonout = config.yaml_to_dict(output, logger=logger)
        if jsonout is None:
            raise Exception("Could not read YAML output of tpm2_pcrread.")

        if hash_alg not in jsonout:
            raise Exception("Invalid hashing algorithm '%s' for reading PCR number %d." % (hash_alg, pcrval))

        # alg_size = Hash_Algorithms.get_hash_size(hash_alg)/4
        alg_size = hash_alg.get_size() // 4
        return '{0:0{1}x}'.format(jsonout[hash_alg][pcrval], alg_size)

    # tpm_random
    def _get_tpm_rand_block(self, size=32):
        # make a temp file for the output
        rand = None
        with tempfile.NamedTemporaryFile() as randpath:
            try:
                command = ["tpm2_getrandom", "-o", randpath.name, str(size)]
                retDict = self.__run(command, outputpaths=randpath.name)
                rand = retDict['fileouts'][randpath.name]
            except Exception as e:
                if not self.tpmrand_warned:
                    logger.warning("TPM randomness not available: %s" % e)
                    self.tpmrand_warned = True
                return None
        return rand

    # tpm_nvram
    def write_key_nvram(self, key):
        owner_pw = self.get_tpm_metadata('owner_pw')

        # write out quote
        with tempfile.NamedTemporaryFile() as keyFile:
            keyFile.write(key)
            keyFile.flush()

            attrs = "ownerread|ownerwrite"
            # TODO(kaifeng) Escaping attrs is probably not required
            if self.tools_version == "3.2":
                self.__run(["tpm2_nvdefine", "-x", "0x1500018", "-a", "0x40000001", "-s", str(config.BOOTSTRAP_KEY_SIZE), "-t", '"%s"' % attrs, "-I", owner_pw, "-P", owner_pw], raiseOnError=False)
                self.__run(["tpm2_nvwrite", "-x", "0x1500018", "-a", "0x40000001", "-P", owner_pw, keyFile.name], raiseOnError=False)
            elif self.tools_version in ["4.0", "4.2"]:
                self.__run(["tpm2_nvdefine", "0x1500018", "-C", "0x40000001", "-s", str(config.BOOTSTRAP_KEY_SIZE), "-a", '"%s"' % attrs, "-p", owner_pw, "-P", owner_pw], raiseOnError=False)
                self.__run(["tpm2_nvwrite", "0x1500018", "-C", "0x40000001", "-P", owner_pw, "-i", keyFile.name], raiseOnError=False)

    def read_ekcert_nvram(self):
        # make a temp file for the quote
        with tempfile.NamedTemporaryFile() as nvpath:

            # Check for RSA EK cert in NVRAM (and get length)
            if self.tools_version == "3.2":
                retDict = self.__run("tpm2_nvlist", raiseOnError=False)
            elif self.tools_version in ["4.0", "4.2"]:
                retDict = self.__run("tpm2_nvreadpublic", raiseOnError=False)
            output = retDict['retout']
            reterr = retDict['reterr']
            code = retDict['code']

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                if self.tools_version == "3.2":
                    raise Exception("tpm2_nvlist for ekcert failed with code " + str(code) + ": " + str(reterr))
                if self.tools_version in ["4.0", "4.2"]:
                    raise Exception("tpm2_nvreadpublic for ekcert failed with code " + str(code) + ": " + str(reterr))

            outjson = config.yaml_to_dict(output, logger=logger)

            if outjson is None or 0x1c00002 not in outjson or "size" not in outjson[0x1c00002]:
                logger.warning("No EK certificate found in TPM NVRAM")
                return None

            ekcert_size = str(outjson[0x1c00002]["size"])

            # Read the RSA EK cert from NVRAM (DER format)
            if self.tools_version == "3.2":
                retDict = self.__run(["tpm2_nvread", "-x", '0x1c00002', "-s", ekcert_size,
                                      "-f", nvpath.name, "-a", "0x01c00002"],
                                     raiseOnError=False, outputpaths=nvpath.name)
            elif self.tools_version in ["4.0", "4.2"]:
                retDict = self.__run(["tpm2_nvread", '0x1c00002', "-s", ekcert_size, "-o", nvpath.name],
                                     raiseOnError=False, outputpaths=nvpath.name)
            output = config.convert(retDict['retout'])
            errout = config.convert(retDict['reterr'])
            code = retDict['code']
            ekcert = retDict['fileouts'][nvpath.name]

            if code != tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_nvread for ekcert failed with code " + str(code) + ": " + str(errout))

        return base64.b64encode(ekcert)

    def read_key_nvram(self):
        owner_pw = self.get_tpm_metadata('owner_pw')
        if self.tools_version == "3.2":
            retDict = self.__run(["tpm2_nvread", "-x", "0x1500018", "-a", "0x40000001", "-s", str(config.BOOTSTRAP_KEY_SIZE), "-P", owner_pw], raiseOnError=False)
        elif self.tools_version in ["4.0", "4.2"]:
            retDict = self.__run(["tpm2_nvread", "0x1500018", "-C", "0x40000001", "-s", str(config.BOOTSTRAP_KEY_SIZE), "-P", owner_pw], raiseOnError=False)

        output = retDict['retout']
        errout = config.convert(retDict['reterr'])
        code = retDict['code']

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
            logger.debug("Invalid key length from NVRAM: %d" % (len(output)))
            return None
        return output

    def __stringify_pcr_keys(self, log: dict) -> None:
        '''Ensure that the PCR indices are strings

        The YAML produced by `tpm2_eventlog`, when loaded by the yaml module,
        uses integer keys in the dicts holding PCR contents.  That does not
        correspond to any JSON data.  This method ensures those keys are
        strings.
        The log is untrusted because it ultimately comes from an untrusted
        source and has been processed by software that has had bugs.'''
        if (not isinstance(log, dict)) or 'pcrs' not in log:
            return
        old_pcrs = log['pcrs']
        if not isinstance(old_pcrs, dict):
            return
        new_pcrs = {}
        for hash_alg, cells in old_pcrs.items():
            if not isinstance(cells, dict):
                new_pcrs[hash_alg] = cells
                continue
            new_pcrs[hash_alg] = {str(index): val for index, val in cells.items()}
        log['pcrs'] = new_pcrs
        return

    def __add_boot_aggregate(self, log: dict) -> None :
        '''Scan the boot event log and calculate possible boot aggregates.

        Hashes are calculated for both sha1 and sha256,
        as well as for 8 or 10 participant PCRs.

        Technically the sha1/10PCR combination is unnecessary, since it has no
        implementation.

        Error conditions caused by improper string formatting etc. are
        ignored. The current assumption is that the boot event log PCR
        values are in decimal encoding, but this is liable to change.'''
        if (not isinstance(log, dict)) or 'pcrs' not in log:
            return
        log['boot_aggregates'] = {}
        for hashalg in log['pcrs'].keys():
            log['boot_aggregates'][hashalg] = []
            for maxpcr in [8,10]:
                try:
                    hashclass = getattr(hashlib,hashalg)
                    h = hashclass()
                    for pcrno in range(0,maxpcr):
                        pcrstrg=log['pcrs'][hashalg][str(pcrno)]
                        pcrhex= '{0:0{1}x}'.format(pcrstrg, h.digest_size*2)
                        h.update(bytes.fromhex(pcrhex))
                    log['boot_aggregates'][hashalg].append(h.hexdigest())
                except Exception:
                    pass

    def parse_binary_bootlog(self, log_bin:bytes) -> typing.Optional[dict]:
        '''Parse and enrich a BIOS boot log

        The input is the binary log.
        The output is the result of parsing and applying other conveniences.'''
        with tempfile.NamedTemporaryFile() as log_bin_file:
            log_bin_file.write(log_bin)
            log_bin_filename = log_bin_file.name
            retDict_tpm2 = self.__run(['tpm2_eventlog', '--eventlog-version=2', log_bin_filename])
        log_parsed_strs = retDict_tpm2['retout']
        log_parsed_data = config.yaml_to_dict(log_parsed_strs, add_newlines=False, logger=logger)
        if log_parsed_data is None:
            return None
        #pylint: disable=import-outside-toplevel
        try:
            from keylime import tpm_bootlog_enrich
        except Exception as e:
            logger.error("Could not load tpm_bootlog_enrich (which depends on %s): %s" % (config.LIBEFIVAR,str(e)))
            return None
        #pylint: enable=import-outside-toplevel
        tpm_bootlog_enrich.enrich(log_parsed_data)
        self.__stringify_pcr_keys(log_parsed_data)
        self.__add_boot_aggregate(log_parsed_data)
        return log_parsed_data

    def _parse_mb_bootlog(self, log_b64:str) -> dict:
        '''Parse and enrich a BIOS boot log

        The input is the base64 encoding of a binary log.
        The output is the result of parsing and applying other conveniences.'''
        log_bin = base64.b64decode(log_b64, validate=True)
        return self.parse_binary_bootlog(log_bin)

    def parse_mb_bootlog(self, mb_measurement_list: str, hash_alg: algorithms.Hash) -> typing.Tuple[dict, typing.Optional[dict], dict, Failure]:
        """ Parse the measured boot log and return its object and the state of the PCRs
        :param mb_measurement_list: The measured boot measurement list
        :param hash_alg: the hash algorithm that should be used for the PCRs
        :returns: Returns a map of the state of the PCRs, measured boot data object and True for success
                  and False in case an error occurred
        """
        failure = Failure(Component.MEASURED_BOOT, ["parser"])
        if mb_measurement_list:
            #TODO add tagging for _parse_mb_bootlog
            mb_measurement_data = self._parse_mb_bootlog(mb_measurement_list)
            if not mb_measurement_data:
                logger.error("Unable to parse measured boot event log. Check previous messages for a reason for error.")
                return {}, None, {}, failure
            log_pcrs = mb_measurement_data.get('pcrs')
            if not isinstance(log_pcrs, dict):
                logger.error("Parse of measured boot event log has unexpected value for .pcrs: %r", log_pcrs)
                failure.add_event("invalid_pcrs", {"got": log_pcrs}, True)
                return {}, None, {}, failure
            pcr_hashes = log_pcrs.get(str(hash_alg))
            if (not isinstance(pcr_hashes, dict)) or not pcr_hashes:
                logger.error("Parse of measured boot event log has unexpected value for .pcrs.%s: %r", str(hash_alg), pcr_hashes)
                failure.add_event("invalid_pcrs_hashes", {"got": pcr_hashes}, True)
                return {}, None, {}, failure
            boot_aggregates = mb_measurement_data.get('boot_aggregates')
            if (not isinstance(boot_aggregates, dict)) or not boot_aggregates:
                logger.error("Parse of measured boot event log has unexpected value for .boot_aggragtes: %r", boot_aggregates)
                failure.add_event("invalid_boot_aggregates", {"got": boot_aggregates}, True)
                return {}, None, {}, failure

            return pcr_hashes, boot_aggregates, mb_measurement_data, failure

        return {}, None, {}, failure
