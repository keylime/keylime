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
import binascii
import ConfigParser
import distutils.spawn
import hashlib
import json
import os
import re
from sets import Set
import sys
import tempfile
import threading
import time

import M2Crypto
from M2Crypto import m2

import cmd_exec
import common
import keylime_logging
import secure_mount
from tpm_abstract import Hash_Algorithms, Encrypt_Algorithms, Sign_Algorithms, AbstractTPM, TPM_Utilities
from tpm_ek_ca import atmel_trusted_keys, trusted_certs

logger = keylime_logging.init_logging('tpm2')

# Read the config file
config = ConfigParser.RawConfigParser()
config.read(common.CONFIG_FILE)

# Are we using legacy tpm2-tools (3.X) or modern (4+)? 
env = os.environ.copy()
env['PATH']=env['PATH']+":%s"%common.TPM_TOOLS_PATH
legacy_tools = distutils.spawn.find_executable("tpm2_takeownership", env['PATH']) is not None
logger.info("Using %s version of tpm2-tools"%("legacy" if legacy_tools else "modern"))

class tpm2(AbstractTPM):

    def __init__(self, need_hw_tpm=False):
        AbstractTPM.__init__(self, need_hw_tpm)
        
        # Shared lock to serialize access to tools
        self.tpmutilLock = threading.Lock()
        
        # We don't know which algs the TPM supports yet
        self.supported['encrypt'] = Set()
        self.supported['hash'] = Set()
        self.supported['sign'] = Set()
        
        # Grab which default algs the config requested
        defaultHash = config.get('cloud_agent', "tpm_hash_alg")
        defaultEncrypt = config.get('cloud_agent', "tpm_encryption_alg")
        defaultSign = config.get('cloud_agent', "tpm_signing_alg")
        
        if self.need_hw_tpm:
            # Start up the TPM
            self.__startup_tpm()
            
            # Figure out which algorithms the TPM supports
            self.__get_tpm_algorithms()
            
            # Ensure TPM supports the defaults requested
            if defaultHash not in self.supported['hash']:
                raise Exception('Unsupported hash algorithm specified: %s!'%(defaultHash))
            if defaultEncrypt not in self.supported['encrypt']:
                raise Exception('Unsupported encryption algorithm specified: %s!'%(defaultEncrypt))
            if defaultSign not in self.supported['sign']:
                raise Exception('Unsupported signing algorithm specified: %s!'%(defaultSign))
        else:
            # Assume their defaults are sane?
            pass
        
        self.defaults['hash'] = defaultHash
        self.defaults['encrypt'] = defaultEncrypt
        self.defaults['sign'] = defaultSign

    def get_tpm_version(self):
        return 2

    def __get_tpm_algorithms(self):
        vendorStr = None
        retDict = self.__run("tpm2_getcap -c algorithms")
        output = retDict['retout']
        code = retDict['code']
        
        if code != AbstractTPM.EXIT_SUCESS:
            raise Exception("get_tpm_algorithms failed with code "+str(code)+": "+str(output))
        
        if legacy_tools:
            # output, human-readable -> yaml
            output = "".join(output)
            output = re.sub(r'TPMA_ALGORITHM for ALG_ID: 0x[0-9a-f]+\s+-\s+([a-z0-9_]+)', r'\1:', output)
            output = output.replace("set", "1")
            output = output.replace("clear", "0")
            output = [output]
        
        retyaml = common.yaml_to_dict(output)
        for algorithm,details in retyaml.iteritems():
            if details["asymmetric"] == 1 and details["object"] == 1 and Encrypt_Algorithms.is_recognized(algorithm):
                self.supported['encrypt'].add(algorithm)
            elif details["hash"] == 1 and Hash_Algorithms.is_recognized(algorithm):
                self.supported['hash'].add(algorithm)
            elif details["asymmetric"] == 1 and details["signing"] == 1 and Sign_Algorithms.is_recognized(algorithm):
                self.supported['sign'].add(algorithm)

    #tpm_exec
    @staticmethod
    def __fingerprint(cmd):
        # Creates a unique-enough ID from the given command 
        fprt = cmd.split()[0]
        if fprt == 'tpm2_nvread':
            if '0x1c00002' in cmd: # read_ekcert_nvram
                fprt += '-ekcert'
            else: # read_key_nvram
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

    def __run(self, cmd, expectedcode=AbstractTPM.EXIT_SUCESS, raiseOnError=True, lock=True, outputpaths=None):
        env = os.environ.copy()
        lib_path = ""
        if 'LD_LIBRARY_PATH' in env:
            lib_path = env['LD_LIBRARY_PATH']
        if 'TPM2TOOLS_TCTI' not in env:
            # Don't clobber existing setting (if present)
            env['TPM2TOOLS_TCTI'] = 'tabrmd:bus_name=com.intel.tss2.Tabrmd'
            # Other (not recommended) options are direct emulator and chardev communications:
            #env['TPM2TOOLS_TCTI'] = 'mssim:port=2321'
            #env['TPM2TOOLS_TCTI'] = 'device:/dev/tpm0'
        env['PATH'] = env['PATH']+":%s"%common.TPM_TOOLS_PATH
        env['LD_LIBRARY_PATH'] = lib_path+":%s"%common.TPM_LIBS_PATH

        # Convert single outputpath to list
        if isinstance(outputpaths, basestring):
            outputpaths = [outputpaths]

        # Handle stubbing the TPM out
        fprt = tpm2.__fingerprint(cmd)
        if common.STUB_TPM and common.TPM_CANNED_VALUES is not None:
            # Use canned values for stubbing 
            jsonIn = common.TPM_CANNED_VALUES
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
                        fileoutEncoded[outputpaths[0]] = base64.b64decode(thisFileout.itervalues().next()).decode("zlib")
                    elif fprt == "tpm2_deluxequote":
                        # quotes need 3 outputs, so we need a consistent way to match them back up when reading
                        quote_msg = ""
                        match = re.search("-m ([^\s]+)", cmd)
                        if match:
                            quote_msg = match.group(1)
                            if "file://quoteMessage" in thisFileout:
                                fileoutEncoded[quote_msg] = base64.b64decode(thisFileout["file://quoteMessage"]).decode("zlib")
                        quote_sig = ""
                        match = re.search("-s ([^\s]+)", cmd)
                        if match:
                            quote_sig = match.group(1)
                            if "file://quoteSignature" in thisFileout:
                                fileoutEncoded[quote_sig] = base64.b64decode(thisFileout["file://quoteSignature"]).decode("zlib")
                        quote_pcr = ""
                        match = re.search("-p ([^\s]+)", cmd)
                        if match:
                            quote_pcr = match.group(1)
                            if "file://quotePCR" in thisFileout:
                                fileoutEncoded[quote_pcr] = base64.b64decode(thisFileout["file://quotePCR"]).decode("zlib")
                    else:
                        raise Exception("Command %s is using multiple files unexpectedly!"%(fprt))

                logger.debug("TPM call '%s' was stubbed out, with a simulated delay of %f sec"%(fprt, thisTiming))
                time.sleep(thisTiming)

                # Package for return
                returnDict = {
                    'retout': thisRetout,
                    'code': thisCode,
                    'fileouts': fileoutEncoded,
                    'timing': thisTiming,
                }
                return returnDict
            elif not lock:
                # non-lock calls don't go to the TPM (just let it pass through) 
                pass
            else:
                # Our command hasn't been canned!
                raise Exception("Command %s not found in canned JSON!"%(fprt))

        numtries = 0
        while True:
            if lock: 
                with self.tpmutilLock:
                    retDict = cmd_exec.run(cmd=cmd, expectedcode=expectedcode, raiseOnError=False, lock=lock, outputpaths=outputpaths, env=env)
            else:
                retDict = cmd_exec.run(cmd=cmd, expectedcode=expectedcode, raiseOnError=False, lock=lock, outputpaths=outputpaths, env=env)
            t0 = retDict['timing']['t0']
            t1 = retDict['timing']['t1']
            code = retDict['code']
            retout = retDict['retout']
            fileouts = retDict['fileouts']

            # keep trying to get quote if a PCR race condition occurred in deluxe quote
            if fprt == "tpm2_deluxequote" and "Error validating calculated PCR composite with quote" in retout:
                numtries += 1
                maxr = self.config.getint('cloud_agent', 'max_retries')
                if numtries >= maxr:
                    logger.error("Agent did not return proper quote due to PCR race condition.")
                    break
                retry = self.config.getfloat('cloud_agent', 'retry_interval')
                logger.info("Failed to get quote %d/%d times, trying again in %f seconds..."%(numtries, maxr, retry))
                time.sleep(retry)
                continue
            else:
                break

        # Don't bother continuing if TPM call failed and we're raising on error 
        if code != expectedcode and raiseOnError:
            raise Exception("Command: %s returned %d, expected %d, output %s"%(cmd, code, expectedcode, retout))

        # Metric output 
        if lock or self.tpmutilLock.locked():
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
            #print "\033[95mTIMING: %s%s\t:%f\toutlines:%d\tfilelines:%d\t%s\033[0m" % (fprt, pad, t1-t0, len(retout), filelen, cmd)
            if common.TPM_BENCHMARK_PATH is not None:
                with open(common.TPM_BENCHMARK_PATH, "ab") as f:
                    f.write("TIMING: %s%s\t:%f\toutlines:%d\tfilelines:%d\t%s\n" % (fprt, pad, t1-t0, len(retout), filelen, cmd))

            # Print out JSON canned values (if requested)
            # NOTE: resulting file will be missing the surrounding braces! (must add '{' and '}' for reading)
            if common.TPM_CANNED_VALUES_PATH is not None:
                with open(common.TPM_CANNED_VALUES_PATH, "ab") as can:
                    fileoutEncoded = {}

                    # Process files
                    if outputpaths is not None and len(outputpaths) > 0:
                        if len(fileouts) == 1 and len(outputpaths) == 1:
                            fileoutEncoded[outputpaths[0]] = base64.b64encode(fileouts.itervalues().next().encode("zlib"))
                        elif fprt == "tpm2_deluxequote":
                            # quotes need 3 outputs, so we need a consistent way to match them back up when reading
                            quote_msg = ""
                            match = re.search("-m ([^\s]+)", cmd)
                            if match:
                                quote_msg = match.group(1)
                                if quote_msg in fileouts:
                                    fileoutEncoded["file://quoteMessage"] = base64.b64encode(fileouts[quote_msg].encode("zlib"))
                            quote_sig = ""
                            match = re.search("-s ([^\s]+)", cmd)
                            if match:
                                quote_sig = match.group(1)
                                if quote_sig in fileouts:
                                    fileoutEncoded["file://quoteSignature"] = base64.b64encode(fileouts[quote_sig].encode("zlib"))
                            quote_pcr = ""
                            match = re.search("-p ([^\s]+)", cmd)
                            if match:
                                quote_pcr = match.group(1)
                                if quote_pcr in fileouts:
                                    fileoutEncoded["file://quotePCR"] = base64.b64encode(fileouts[quote_pcr].encode("zlib"))
                        else:
                            raise Exception("Command %s is using multiple files unexpectedly!"%(fprt))

                    # tpm_cexec will need to know the nonce 
                    nonce = ""
                    match = re.search("-q ([\w]+)", cmd)
                    if match:
                        nonce = binascii.a2b_hex(match.group(1))

                    jsonObj = {'type':fprt, 'retout':retout, 'fileout':fileoutEncoded, 'cmd':cmd, 'timing':t1-t0, 'code':code, 'nonce':nonce}
                    can.write("\"%s\": %s,\n"%(fprt, json.dumps(jsonObj, indent=4, sort_keys=True)))

        return retDict


    #tpm_initialize
    def __startup_tpm(self):
        retDict = self.__run("tpm2_startup -c")
        output = retDict['retout']
        code = retDict['code']
        if code != AbstractTPM.EXIT_SUCESS:
            raise Exception("Error initializing emulated TPM with TPM2_Startup: %s"+str(code)+": "+str(output))

    def __create_ek(self, asym_alg=None):
        # this function is intended to be idempotent 
        if asym_alg is None:
            asym_alg = self.defaults['encrypt']
        
        current_handle = self.get_tpm_metadata("ek_handle")
        owner_pw = self.get_tpm_metadata("owner_pw")
        
        # clear out old handle before starting again (give idempotence)
        if current_handle is not None and owner_pw is not None:
            logger.info("Flushing old ek handle: %s"%hex(current_handle))
            
            retDict = self.__run("tpm2_getcap -c handles-persistent", raiseOnError=False)
            output = retDict['retout']
            code = retDict['code']
            
            if code != AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_getcap failed with code "+str(code)+": "+str(output))
            
            outyaml = common.yaml_to_dict(output)
            if outyaml is not None and current_handle in outyaml:
                if legacy_tools:
                    retDict = self.__run("tpm2_evictcontrol -A o -c %s -P %s"%(hex(current_handle), owner_pw), raiseOnError=False)
                else:
                    retDict = self.__run("tpm2_evictcontrol -a o -c %s -P %s"%(hex(current_handle), owner_pw), raiseOnError=False)
                output = retDict['retout']
                code = retDict['code']
                
                if code != AbstractTPM.EXIT_SUCESS:
                    logger.info("Failed to flush old ek handle: %s.  Code %s"%(hex(current_handle), str(code)+": "+str(output)))
                
                self._set_tpm_metadata('ek_handle', None)
                self._set_tpm_metadata('ek_pw', None)
        
        # make sure an ownership pw is set
        if owner_pw is None:
            owner_pw = TPM_Utilities.random_password(20)
            self._set_tpm_metadata('owner_pw', owner_pw)
        ek_pw = TPM_Utilities.random_password(20)
        
        # create a new ek 
        with tempfile.NamedTemporaryFile() as tmppath:
            cmdargs = {
                'asymalg': asym_alg,
                'ekpubfile': tmppath.name,
                'ekpw': ek_pw,
                'opw': owner_pw,
                'epw': owner_pw
            }
            if legacy_tools:
                command = "tpm2_getpubek -H 0x81010007 -g {asymalg} -f {ekpubfile} -P {ekpw} -o {opw} -e {epw}".format(**cmdargs)
            else:
                command = "tpm2_createek -c - -G {asymalg} -p {ekpubfile} -P {ekpw} -o {opw} -e {epw}".format(**cmdargs)
            retDict = self.__run(command, raiseOnError=False, outputpaths=tmppath.name)
            output = retDict['retout']
            code = retDict['code']
            ek_tpm = retDict['fileouts'][tmppath.name]
            
            if code != AbstractTPM.EXIT_SUCESS:
                raise Exception("createek failed with code "+str(code)+": "+str(output))
            
            if legacy_tools:
                handle = int(0x81010007)
            else:
                handle = None
                retyaml = common.yaml_to_dict(output)
                if "persistent-handle" in retyaml:
                    handle = retyaml["persistent-handle"]
            
            self._set_tpm_metadata('ek_handle', handle)
            self._set_tpm_metadata('ek_pw', ek_pw)
            self._set_tpm_metadata('ek_tpm', base64.b64encode(ek_tpm))
        
        return

    def __take_ownership(self, config_pw):
        # if no ownerpassword
        if config_pw == 'generate':
            logger.info("Generating random TPM owner password")
            owner_pw = TPM_Utilities.random_password(20)
        else:
            logger.info("Taking ownership with config provided TPM owner password: %s"%config_pw)
            owner_pw = config_pw
        
        if legacy_tools:
            retDict = self.__run("tpm2_takeownership -c", raiseOnError=False)
            retDict = self.__run("tpm2_takeownership -o %s -e %s"%(owner_pw, owner_pw), raiseOnError=False)
        else:
            retDict = self.__run("tpm2_changeauth -o %s -e %s"%(owner_pw, owner_pw), raiseOnError=False)
        
        output = retDict['retout']
        code = retDict['code']
        if code != AbstractTPM.EXIT_SUCESS:
            # if we fail, see if already owned with this pw
            if legacy_tools:
                retDict = self.__run("tpm2_takeownership -o %s -e %s -O %s -E %s"%(owner_pw, owner_pw, owner_pw, owner_pw), raiseOnError=False)
            else:
                retDict = self.__run("tpm2_changeauth -o %s -e %s -O %s -E %s"%(owner_pw, owner_pw, owner_pw, owner_pw), raiseOnError=False)
            
            output = retDict['retout']
            code = retDict['code']
            if code != AbstractTPM.EXIT_SUCESS:
                # ut-oh, already owned but not with provided pw!
                raise Exception("Owner password unknown, TPM reset required. Code %s"+str(code)+": "+str(output))
        
        self._set_tpm_metadata('owner_pw', owner_pw)
        logger.info("TPM Owner password confirmed: %s"%owner_pw)

    def __get_pub_ek(self): # assumes that owner_pw is correct at this point
        handle = self.get_tpm_metadata('ek_handle')
        if handle is None:
            raise Exception("create_ek has not been run yet?")
        #make a temp file for the output 
        with tempfile.NamedTemporaryFile() as tmppath:
            # generates pubek.pem
            if legacy_tools:
                retDict = self.__run("tpm2_readpublic -H %s -o %s -f pem"%(hex(handle), tmppath.name), raiseOnError=False, outputpaths=tmppath.name)
            else:
                retDict = self.__run("tpm2_readpublic -c %s -o %s -f pem"%(hex(handle), tmppath.name), raiseOnError=False, outputpaths=tmppath.name)
            
            output = retDict['retout']
            code = retDict['code']
            ek = retDict['fileouts'][tmppath.name]
            if code != AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_readpublic failed with code "+str(code)+": "+str(output))
        
        self._set_tpm_metadata('ek', ek)

    def __get_pub_aik(self):
        """Retrieves the PEM version of the public AIK.
        
        Helper function for '__create_aik', required for legacy (v3) of
        tpm2-tools since tpm2_getpubak does not support outputting public AIK
        in the required PEM format. Note that 'aik_handle' metadata must
        have been set before running this function.  Function sets the
        'aik' metadata.
        """

        if not legacy_tools:
            logger.error("The get_pub_aik method does not apply to modern tpm2-tools!")
            return
        
        handle = self.get_tpm_metadata('aik_handle')
        if handle is None:
            raise Exception("tpm2_getpubak has not been run yet?")
        #make a temp file for the output 
        with tempfile.NamedTemporaryFile() as akpubfile:
            # generates pubak.pem
            retDict = self.__run("tpm2_readpublic -H %s -o %s -f pem"%(hex(handle), akpubfile.name), raiseOnError=False, outputpaths=akpubfile.name)
            output = retDict['retout']
            code = retDict['code']
            pem = retDict['fileouts'][akpubfile.name]
            
            if code != AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_readpublic failed with code "+str(code)+": "+str(output))
            
            if pem == "":
                raise Exception("unable to read public aik from create identity.  Is your tpm2-tools installation up to date?")
        
        self._set_tpm_metadata('aik', pem)

    def __create_aik(self, activate, asym_alg=None, hash_alg=None, sign_alg=None):
        if hash_alg is None:
            hash_alg = self.defaults['hash']
        if asym_alg is None:
            asym_alg = self.defaults['encrypt']
        if sign_alg is None:
            sign_alg = self.defaults['sign']
        
        owner_pw = self.get_tpm_metadata('owner_pw')
        
        # clear out old handle before starting again (give idempotence)
        if self.get_tpm_metadata('aik') is not None and self.get_tpm_metadata('aik_name') is not None:
            aik_handle = self.get_tpm_metadata('aik_handle')
            logger.info("Flushing old ak handle: %s"%hex(aik_handle))
            
            retDict = self.__run("tpm2_getcap -c handles-persistent", raiseOnError=False)
            output = retDict['retout']
            code = retDict['code']
            
            if code != AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_getcap failed with code "+str(code)+": "+str(output))
            
            if legacy_tools:
                # output, human-readable -> yaml
                output = "".join(output)
                output = output.replace("0x", " - 0x")
                output = [output]
            
            outyaml = common.yaml_to_dict(output)
            if outyaml is not None and aik_handle in outyaml:
                if legacy_tools:
                    retDict = self.__run("tpm2_evictcontrol -A o -c %s -P %s"%(hex(aik_handle), owner_pw), raiseOnError=False)
                else:
                    retDict = self.__run("tpm2_evictcontrol -a o -c %s -P %s"%(hex(aik_handle), owner_pw), raiseOnError=False)
                
                output = retDict['retout']
                code = retDict['code']
                
                if code != AbstractTPM.EXIT_SUCESS:
                    logger.info("Failed to flush old ak handle: %s.  Code %s"%(hex(aik_handle), str(code)+": "+str(output)))
                
                self._set_tpm_metadata('aik', None)
                self._set_tpm_metadata('aik_name', None)
                self._set_tpm_metadata('aik_pw', None)
                self._set_tpm_metadata('aik_handle', None)
        
        logger.debug("Creating a new AIK identity")
        
        # We need an ek handle to make an aik
        ek_handle = self.get_tpm_metadata("ek_handle")
        if ek_handle is None:
            raise Exception("Failed to create AIK, since EK has not yet been created!")
        
        aik_pw = TPM_Utilities.random_password(20)
        #make a temp file for the output
        with tempfile.NamedTemporaryFile() as akpubfile:
            cmdargs = {
                'ekhandle': hex(ek_handle),
                'akpubfile': akpubfile.name,
                'asymalg': asym_alg,
                'hashalg': hash_alg,
                'signalg': sign_alg,
                'epw': owner_pw,
                'opw': owner_pw,
                'apw': aik_pw
            }
            if legacy_tools:
                command = "tpm2_getpubak -E {ekhandle} -k 0x81010008 -g {asymalg} -D {hashalg} -s {signalg} -f {akpubfile} -e {epw} -P {apw} -o {opw}".format(**cmdargs)
            else:
                command = "tpm2_createak -C {ekhandle} -k - -G {asymalg} -D {hashalg} -s {signalg} -p {akpubfile} -f pem -e {epw} -P {apw} -o {opw}".format(**cmdargs)
            retDict = self.__run(command, outputpaths=akpubfile.name)
            retout = retDict['retout']
            code = retDict['code']
            
            if code != AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_createak failed with code "+str(code)+": "+str(output))
            
            yamlout = common.yaml_to_dict(retout)
            akname = yamlout['loaded-key']['name']
            
            if legacy_tools:
                if 'loaded-key' not in yamlout or 'name' not in yamlout['loaded-key']:
                    raise Exception("tpm2_createak failed to create aik: return "+str(retout))
                
                handle = int(0x81010008)
                
                # get and persist the pem (not returned by tpm2_getpubak)
                self._set_tpm_metadata('aik_handle', handle)
                self.__get_pub_aik()
            else:
                if 'loaded-key' not in yamlout or 'ak-persistent-handle' not in yamlout:
                    raise Exception("tpm2_createak failed to create aik: return "+str(retout))
                
                handle = yamlout['ak-persistent-handle']
                pem = retDict['fileouts'][akpubfile.name]
                if pem == "":
                    raise Exception("unable to read public aik from create identity.  Is your tpm2-tools installation up to date?")
                
                # persist the pem
                self._set_tpm_metadata('aik_handle', handle)
                self._set_tpm_metadata('aik', pem)
        
        # persist common results
        self._set_tpm_metadata('aik_name', akname)
        self._set_tpm_metadata('aik_pw', aik_pw)

    def flush_keys(self):
        logger.debug("Flushing keys from TPM...") 
        retDict = self.__run("tpm2_getcap -c handles-persistent")
        retout = retDict['retout']
        code = retDict['code']
        
        if code != AbstractTPM.EXIT_SUCESS:
            logger.debug("tpm2_getcap failed with code "+str(code)+": "+str(retout))
        
        if legacy_tools:
            # output, human-readable -> yaml
            retout = "".join(retout)
            retout = retout.replace("0x", " - 0x")
            retout = [retout]
        
        owner_pw = self.get_tpm_metadata("owner_pw")
        yamlout = common.yaml_to_dict(retout)
        for key in yamlout:
            logger.debug("Flushing key handle %s"%hex(key))
            if legacy_tools:
                self.__run("tpm2_evictcontrol -A o -c %s -P %s"%(hex(key), owner_pw), raiseOnError=False)
            else:
                self.__run("tpm2_evictcontrol -a o -c %s -P %s"%(hex(key), owner_pw), raiseOnError=False)

    def encryptAIK(self, uuid, pubaik, pubek, ek_tpm, aik_name):
        pubaikFile = None
        pubekFile = None
        challengeFile = None
        keyblob = None
        blobpath = None
        
        if ek_tpm is None or aik_name is None:
            logger.error("Missing parameters for encryptAIK")
            return None
        
        try:
            # write out the public EK
            efd, etemp = tempfile.mkstemp()
            pubekFile = open(etemp, "wb")
            pubekFile.write(base64.b64decode(ek_tpm))
            pubekFile.close()
            os.close(efd)
            
            # write out the challenge
            challenge = TPM_Utilities.random_password(32)
            keyfd, keypath = tempfile.mkstemp()
            challengeFile = open(keypath, "wb")
            challengeFile.write(challenge)
            challengeFile.close()
            os.close(keyfd)
            
            # create temp file for the blob
            blobfd, blobpath = tempfile.mkstemp()
            
            cmdargs = {
                'akname': aik_name,
                'ekpub': pubekFile.name,
                'blobout': blobpath,
                'challenge': challengeFile.name
            }
            if legacy_tools:
                command = "tpm2_makecredential -T none -e {ekpub} -s {challenge} -n {akname} -o {blobout}".format(**cmdargs)
            else:
                command = "tpm2_makecredential -e {ekpub} -s {challenge} -n {akname} -o {blobout} --no-tpm".format(**cmdargs)
            self.__run(command, lock=False)
            
            logger.info("Encrypting AIK for UUID %s"%uuid)
            
            # read in the blob
            f = open(blobpath, "rb")
            keyblob = base64.b64encode(f.read())
            f.close()
            os.close(blobfd)
            
            # read in the aes key
            key = base64.b64encode(challenge)
            
        except Exception as e:
            logger.error("Error encrypting AIK: "+str(e))
            logger.exception(e)
            return None
        finally:
            if pubekFile is not None:
                os.remove(pubekFile.name)
            if challengeFile is not None:
                os.remove(challengeFile.name)
            if blobpath is not None:
                os.remove(blobpath)
        return (keyblob, key)

    def activate_identity(self, keyblob):
        owner_pw = self.get_tpm_metadata('owner_pw')
        aik_keyhandle = self.get_tpm_metadata('aik_handle')
        ek_keyhandle = self.get_tpm_metadata('ek_handle')
        
        keyblobFile = None
        secpath = None
        try:
            # write out key blob
            kfd, ktemp = tempfile.mkstemp()
            keyblobFile = open(ktemp, "wb")
            keyblobFile.write(base64.b64decode(keyblob))
            keyblobFile.close()
            os.close(kfd)
            
            # ok lets write out the key now
            secdir = secure_mount.mount() # confirm that storage is still securely mounted
                
            secfd, secpath = tempfile.mkstemp(dir=secdir)
            
            cmdargs = {
                'akhandle': hex(aik_keyhandle),
                'ekhandle': hex(ek_keyhandle),
                'keyblobfile': keyblobFile.name,
                'credfile': secpath,
                'apw': self.get_tpm_metadata('aik_pw'),
                'epw': owner_pw
            }
            if legacy_tools:
                command = "tpm2_activatecredential -H {akhandle} -k {ekhandle} -f {keyblobfile} -o {credfile} -P {apw} -e {epw}".format(**cmdargs)
            else:
                command = "tpm2_activatecredential -c {akhandle} -C {ekhandle} -f {keyblobfile} -o {credfile} -P {apw} -E {epw}".format(**cmdargs)
            retDict = self.__run(command, outputpaths=secpath)
            retout = retDict['retout']
            code = retDict['code']
            fileout = retDict['fileouts'][secpath]
            logger.info("AIK activated.")
            
            key = base64.b64encode(fileout)
            os.close(secfd)
            os.remove(secpath)
            
        except Exception as e:
            logger.error("Error decrypting AIK: "+str(e))
            logger.exception(e)
            return False
        finally:
            if keyblobFile is not None:
                os.remove(keyblobFile.name)
            if secpath is not None and os.path.exists(secpath):
                os.remove(secpath)
        return key

    def verify_ek(self, ekcert, ekpem):
        """Verify that the provided EK certificate is signed by a trusted root
        :param ekcert: The Endorsement Key certificate in DER format
        :param ekpem: the endorsement public key in PEM format
        :returns: True if the certificate can be verified, false otherwise
        """
        #openssl x509 -inform der -in certificate.cer -out certificate.pem
        try:
            ek509 = M2Crypto.X509.load_cert_der_string(ekcert)
            ekcertpem = ek509.get_pubkey().get_rsa().as_pem(cipher=None)
            
            # Make sure given ekcert is for their ek
            if str(ekpem) != str(ekcertpem):
                logger.error("Public EK does not match EK certificate")
                return False
            
            for signer in trusted_certs:
                signcert = M2Crypto.X509.load_cert_string(trusted_certs[signer])
                signkey = signcert.get_pubkey()
                if ek509.verify(signkey) == 1:
                    logger.debug("EK cert matched signer %s"%signer)
                    return True
        except Exception as e:
            # Log the exception so we don't lose the raw message 
            logger.exception(e)
            raise Exception("Error processing ek/ekcert. Does this TPM have a valid EK?"), None, sys.exc_info()[2]
        
        logger.error("No Root CA matched EK Certificate")
        return False

    def get_tpm_manufacturer(self):
        vendorStr = None
        retDict = self.__run("tpm2_getcap -c properties-fixed")
        output = retDict['retout']
        code = retDict['code']
        
        if code != AbstractTPM.EXIT_SUCESS:
            raise Exception("get_tpm_manufacturer failed with code "+str(code)+": "+str(output))
        
        retyaml = common.yaml_to_dict(output)
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
        self.__take_ownership(config_pw)

        self.__create_ek()

        self.__get_pub_ek()

        ekcert = self.read_ekcert_nvram()
        self._set_tpm_metadata('ekcert', ekcert)

        # if no AIK created, then create one
        self.__create_aik(self_activate)

        return self.get_tpm_metadata('ek'), self.get_tpm_metadata('ekcert'), self.get_tpm_metadata('aik'), self.get_tpm_metadata('ek_tpm'), self.get_tpm_metadata('aik_name')


    #tpm_quote
    def __pcr_mask_to_list(self, mask, hash_alg):
        pcr_list = []
        ima_appended = ""
        for pcr in range(24):
            if TPM_Utilities.check_mask(mask, pcr):
                if hash_alg != Hash_Algorithms.SHA1 and pcr == common.IMA_PCR:
                    # IMA is only in SHA1 format
                    ima_appended = "+sha1:"+str(pcr)
                else:
                    pcr_list.append(str(pcr))
        return ",".join(pcr_list)+ima_appended

    def create_deep_quote(self, nonce, data=None, vpcrmask=AbstractTPM.EMPTYMASK, pcrmask=AbstractTPM.EMPTYMASK):
        raise Exception("vTPM support and deep quotes not yet implemented with TPM 2.0!")

    def create_quote(self, nonce, data=None, pcrmask=AbstractTPM.EMPTYMASK, hash_alg=None):
        if hash_alg is None:
            hash_alg = self.defaults['hash']
        
        quote = ""
        with tempfile.NamedTemporaryFile() as quotepath:
            with tempfile.NamedTemporaryFile() as sigpath:
                with tempfile.NamedTemporaryFile() as pcrpath:
                    keyhandle = self.get_tpm_metadata('aik_handle')
                    aik_pw = self.get_tpm_metadata('aik_pw')
                    
                    if pcrmask is None:
                        pcrmask = AbstractTPM.EMPTYMASK
                    pcrlist = self.__pcr_mask_to_list(pcrmask, hash_alg)

                    with self.tpmutilLock:
                        if data is not None:
                            self.__run("tpm2_pcrreset %d"%common.TPM_DATA_PCR, lock=False)
                            self.extendPCR(pcrval=common.TPM_DATA_PCR, hashval=self.hashdigest(data), lock=False)
                        
                        cmdargs = {
                            'aik_handle': hex(keyhandle),
                            'hashalg' : hash_alg,
                            'pcrlist': pcrlist,
                            'nonce': binascii.hexlify(nonce),
                            'outquote': quotepath.name,
                            'outsig': sigpath.name,
                            'outpcr': pcrpath.name,
                            'akpw': aik_pw
                        }
                        if legacy_tools:
                            command = "tpm2_quote -k {aik_handle} -L {hashalg}:{pcrlist} -q {nonce} -m {outquote} -s {outsig} -p {outpcr} -G {hashalg} -P {akpw}".format(**cmdargs)
                        else:
                            command = "tpm2_deluxequote -C {aik_handle} -L {hashalg}:{pcrlist} -q {nonce} -m {outquote} -s {outsig} -p {outpcr} -G {hashalg} -P {akpw}".format(**cmdargs)
                        retDict = self.__run(command, lock=False, outputpaths=[quotepath.name, sigpath.name, pcrpath.name])
                        retout = retDict['retout']
                        code = retDict['code']
                        quoteraw = retDict['fileouts'][quotepath.name]
                        sigraw = retDict['fileouts'][sigpath.name]
                        pcrraw = retDict['fileouts'][pcrpath.name]
                        quote = base64.b64encode(quoteraw.encode("zlib"))+":"+base64.b64encode(sigraw.encode("zlib"))+":"+base64.b64encode(pcrraw.encode("zlib"))

        return 'r'+quote

    def __checkdeepquote_c(self, hAIK, vAIK, deepquoteFile, nonce):
        raise Exception("vTPM support and deep quotes not yet implemented with TPM 2.0!")

    def check_deep_quote(self, nonce, data, quote, vAIK, hAIK, vtpm_policy={}, tpm_policy={}, ima_measurement_list=None, ima_whitelist={}):
        raise Exception("vTPM support and deep quotes not yet implemented with TPM 2.0!")

    def __check_quote_c(self, pubaik, nonce, quoteFile, sigFile, pcrFile, hash_alg):

        if common.STUB_TPM and common.TPM_CANNED_VALUES is not None:
            jsonIn = common.TPM_CANNED_VALUES
            if 'tpm2_deluxequote' in jsonIn and 'nonce' in jsonIn['tpm2_deluxequote']:
                # JSON unicode-ifies strings, and C calls require byte strings (str)
                nonce = str(jsonIn['tpm2_deluxequote']['nonce'])
            else:
                raise Exception("Could not get quote nonce from canned JSON!")

        cmdargs = {
            'pubak': pubaik,
            'quotefile' : quoteFile,
            'sigfile': sigFile,
            'pcrfile': pcrFile,
            'hashalg': hash_alg,
            'nonce': binascii.hexlify(nonce)
        }
        command = "tpm2_checkquote -c {pubak} -m {quotefile} -s {sigfile} -p {pcrfile} -G {hashalg} -q {nonce}"
        retDict = self.__run(command.format(**cmdargs), lock=False)
        return retDict

    def check_quote(self, nonce, data, quote, aikFromRegistrar, tpm_policy={}, ima_measurement_list=None, ima_whitelist={}, hash_alg=None):
        if hash_alg is None:
            hash_alg = self.defaults['hash']
        
        quoteFile = None
        aikFile = None
        sigFile = None
        pcrFile = None

        if quote[0] != 'r':
            raise Exception("Invalid quote type %s"%quote[0])
        quote = quote[1:]
        
        quote_tokens = quote.split(":")
        if len(quote_tokens) < 3:
            raise Exception("Quote is not compound! %s"%quote)
        
        quoteblob = base64.b64decode(quote_tokens[0]).decode("zlib")
        sigblob = base64.b64decode(quote_tokens[1]).decode("zlib")
        pcrblob = base64.b64decode(quote_tokens[2]).decode("zlib")
        
        try:
            # write out quote
            qfd, qtemp = tempfile.mkstemp()
            quoteFile = open(qtemp, "wb")
            quoteFile.write(quoteblob)
            quoteFile.close()
            os.close(qfd)

            # write out sig
            sfd, stemp = tempfile.mkstemp()
            sigFile = open(stemp, "wb")
            sigFile.write(sigblob)
            sigFile.close()
            os.close(sfd)

            # write out pcr
            pfd, ptemp = tempfile.mkstemp()
            pcrFile = open(ptemp, "wb")
            pcrFile.write(pcrblob)
            pcrFile.close()
            os.close(pfd)

            afd, atemp = tempfile.mkstemp()
            aikFile = open(atemp, "w")
            aikFile.write(aikFromRegistrar)
            aikFile.close()
            os.close(afd)

            retDict = self.__check_quote_c(aikFile.name, nonce, quoteFile.name, sigFile.name, pcrFile.name, hash_alg)
            retout = retDict['retout']
            code = retDict['code']
        except Exception as e:
            logger.error("Error verifying quote: "+str(e))
            logger.exception(e)
            return False
        finally:
            if aikFile is not None:
                os.remove(aikFile.name)
            if quoteFile is not None:
                os.remove(quoteFile.name)
            if sigFile is not None:
                os.remove(sigFile.name)
            if pcrFile is not None:
                os.remove(pcrFile.name)

        if len(retout) < 1 or code != AbstractTPM.EXIT_SUCESS:
            logger.error("Failed to validate signature, output: %s"%retout)
            return False

        pcrs = []
        yamlout = common.yaml_to_dict(retout)
        if "pcrs" in yamlout:
            if hash_alg in yamlout["pcrs"]:
                alg_size = Hash_Algorithms.get_hash_size(hash_alg)/4
                for pcrval, hashval in yamlout["pcrs"][hash_alg].iteritems():
                    pcrs.append("PCR " + str(pcrval) + " " + '{0:0{1}x}'.format(hashval, alg_size))
            # IMA is always in SHA1 format, so don't leave it behind!
            if hash_alg != Hash_Algorithms.SHA1:
                if Hash_Algorithms.SHA1 in yamlout["pcrs"] and common.IMA_PCR in yamlout["pcrs"][Hash_Algorithms.SHA1]:
                    sha1_size = Hash_Algorithms.get_hash_size(Hash_Algorithms.SHA1)/4
                    ima_val = yamlout["pcrs"][Hash_Algorithms.SHA1][common.IMA_PCR]
                    pcrs.append("PCR " + str(common.IMA_PCR) + " " + '{0:0{1}x}'.format(ima_val, sha1_size))

        if len(pcrs) == 0:
            pcrs = None

        return self.check_pcrs(tpm_policy, pcrs, data, False, ima_measurement_list, ima_whitelist)

    def extendPCR(self, pcrval, hashval, hash_alg=None, lock=True):
        if hash_alg is None:
            hash_alg = self.defaults['hash']
        
        self.__run("tpm2_pcrextend %d:%s=%s"%(pcrval, hash_alg, hashval), lock=lock)

    def readPCR(self, pcrval, hash_alg=None):
        if hash_alg is None:
            hash_alg = self.defaults['hash']
        
        output = self.__run("tpm2_pcrlist")['retout']
        yamlout = common.yaml_to_dict(output)
        
        if hash_alg not in yamlout:
            raise Exception("Invalid hashing algorithm '%s' for reading PCR number %d."%(hash_alg, pcrval))
        
        alg_size = Hash_Algorithms.get_hash_size(hash_alg)/4
        return '{0:0{1}x}'.format(yamlout[hash_alg][pcrval], alg_size)


    #tpm_random
    def _get_tpm_rand_block(self, size=4096):
        #make a temp file for the output 
        rand = None
        with tempfile.NamedTemporaryFile() as randpath:
            try:
                command = "tpm2_getrandom -o %s %d" % (randpath.name, size)
                retDict = self.__run(command, outputpaths=randpath.name)
                retout = retDict['retout']
                code = retDict['code']
                rand = retDict['fileouts'][randpath.name]
            except Exception as e:
                if not self.tpmrand_warned:
                    logger.warn("TPM randomness not available: %s"%e)
                    self.tpmrand_warned = True
                return None
        return rand


    #tpm_nvram
    def write_key_nvram(self, key):
        owner_pw = self.get_tpm_metadata('owner_pw')
        
        # write out quote
        with tempfile.NamedTemporaryFile() as keyFile:
            keyFile.write(key)
            keyFile.flush()
            
            attrs = "ownerread|policywrite|ownerwrite"
            if legacy_tools:
                self.__run("tpm2_nvdefine -x 0x1500018 -a 0x40000001 -s %s -t \"%s\" -I %s -P %s"%(common.BOOTSTRAP_KEY_SIZE, attrs, owner_pw, owner_pw), raiseOnError=False)
            else:
                self.__run("tpm2_nvdefine -x 0x1500018 -a 0x40000001 -s %s -t \"%s\" -p %s -P %s"%(common.BOOTSTRAP_KEY_SIZE, attrs, owner_pw, owner_pw), raiseOnError=False)
            
            self.__run("tpm2_nvwrite -x 0x1500018 -a 0x40000001 -P %s %s"%(owner_pw, keyFile.name), raiseOnError=False)
        return

    def read_ekcert_nvram(self):
        #make a temp file for the quote 
        with tempfile.NamedTemporaryFile() as nvpath:

            # Check for RSA EK cert in NVRAM (and get length)
            retDict = self.__run("tpm2_nvlist", raiseOnError=False)
            output = retDict['retout']
            code = retDict['code']

            if code != AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_nvlist for ekcert failed with code "+str(code)+": "+str(output))

            outyaml = common.yaml_to_dict(output)
            if outyaml is None or 0x1c00002 not in outyaml or "size" not in outyaml[0x1c00002]:
                logger.warn("No EK certificate found in TPM NVRAM")
                return None

            ekcert_size = outyaml[0x1c00002]["size"]

            # Read the RSA EK cert from NVRAM (DER format)
            retDict = self.__run("tpm2_nvread -x 0x1c00002 -s %s -f %s"%(ekcert_size, nvpath.name), raiseOnError=False, outputpaths=nvpath.name)
            output = retDict['retout']
            code = retDict['code']
            ekcert = retDict['fileouts'][nvpath.name]

            if code != AbstractTPM.EXIT_SUCESS:
                raise Exception("tpm2_nvread for ekcert failed with code "+str(code)+": "+str(output))

        return base64.b64encode(ekcert)

    def read_key_nvram(self):
        owner_pw = self.get_tpm_metadata('owner_pw')

        retDict = self.__run("tpm2_nvread -x 0x1500018 -a 0x40000001 -s %s -P %s"%(common.BOOTSTRAP_KEY_SIZE, owner_pw), raiseOnError=False)
        output = retDict['retout']
        code = retDict['code']

        if code != AbstractTPM.EXIT_SUCESS and len(output) > 0 and "ERROR: Failed to read NVRAM public area at index" in "\n".join(output):
            logger.debug("No stored U in TPM NVRAM")
            return None
        elif code != AbstractTPM.EXIT_SUCESS:
            raise Exception("nv_readvalue failed with code "+str(code)+": "+str(output))

        if len(output) != common.BOOTSTRAP_KEY_SIZE:
            logger.debug("Invalid key length from NVRAM: %d"%(len(output)))
            return None
        return output
