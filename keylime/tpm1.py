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
import hashlib
import M2Crypto
import os
import re
import string
import subprocess
import sys
import tempfile
import threading
import time
import yaml
import zlib
import codecs
try:
    from yaml import CSafeLoader as SafeLoader, CSafeDumper as SafeDumper
except ImportError:
    from yaml import SafeLoader as SafeLoader, SafeDumper as SafeDumper

from M2Crypto import m2
from keylime import crypto
from keylime import cmd_exec
from keylime import common
from keylime import keylime_logging
from keylime import ima
from keylime import secure_mount
from keylime import tpm_abstract
from keylime import tpm_ek_ca

logger = keylime_logging.init_logging('tpm1')

# read the config file
config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)


class tpm1(tpm_abstract.AbstractTPM):

    def __init__(self, need_hw_tpm=False):
        tpm_abstract.AbstractTPM.__init__(self, need_hw_tpm)

        # shared lock to serialize access to tools
        self.tpmutilLock = threading.Lock()

        # TPM 1.2 supports fixed set of algorithms
        self.supported['hash'] = set([tpm_abstract.Hash_Algorithms.SHA1])
        self.supported['encrypt'] = set([tpm_abstract.Encrypt_Algorithms.RSA])
        self.supported['sign'] = set([tpm_abstract.Sign_Algorithms.RSASSA])

        self.defaults['hash'] = tpm_abstract.Hash_Algorithms.SHA1
        self.defaults['encrypt'] = tpm_abstract.Encrypt_Algorithms.RSA
        self.defaults['sign'] = tpm_abstract.Sign_Algorithms.RSASSA

    def get_tpm_version(self):
        return 1

    #tpm_exec
    @staticmethod
    def __fingerprint(cmd):
        # Creates a unique-enough ID from the given command
        fprt = cmd.split()[0]
        if fprt == 'getcapability':
            if '-cap 5' in cmd: # is_tpm_owned
                fprt += '-cap5'
            elif '-cap 1a' in cmd: # get_tpm_manufacturer
                fprt += '-cap1a'
        elif fprt == 'nv_readvalue':
            if '-in 1000f000' in cmd: # read_ekcert_nvram
                fprt += '-in1000f000'
            elif '-in 1 ' in cmd: # read_key_nvram
                fprt += '-in1'
        else:
            # other commands are already unique
            pass
        return fprt

    def __run(self,cmd,expectedcode=tpm_abstract.AbstractTPM.EXIT_SUCESS,raiseOnError=True,lock=True,outputpaths=None):
        env = os.environ.copy()
        env['TPM_SERVER_PORT']='9998'
        env['TPM_SERVER_NAME']='localhost'
        env['PATH']=env['PATH']+":%s"%common.TPM_TOOLS_PATH

        # Backwards compat with string input (force all to be dict)
        if isinstance(outputpaths, str):
            outputpaths = [outputpaths]

        # Handle stubbing the TPM out
        fprt = tpm1.__fingerprint(cmd)
        if common.STUB_TPM and common.TPM_CANNED_VALUES is not None:
            # Use canned values for stubbing
            yamlIn = common.TPM_CANNED_VALUES
            if fprt in yamlIn:
                # The value we're looking for has been canned!
                thisTiming = yamlIn[fprt]['timing']
                thisRetout = yamlIn[fprt]['retout']
                thisCode = yamlIn[fprt]['code']
                thisFileout = yamlIn[fprt]['fileout']
                fileoutEncoded = {}

                # Decode files that are supplied
                if outputpaths is not None and len(outputpaths) == 1:
                    if thisFileout != '':
                        fileoutEncoded[outputpaths[0]] = zlib.decompress(base64.b64decode(thisFileout))

                logger.debug("TPM call '%s' was stubbed out, with a simulated delay of %f sec"%(fprt,thisTiming))
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
                raise Exception("Command %s not found in canned YAML!"%(fprt))

        numtries = 0
        while True:
            if lock:
                with self.tpmutilLock:
                    retDict = cmd_exec.run(cmd=cmd,expectedcode=expectedcode,raiseOnError=False,lock=lock,outputpaths=outputpaths,env=env)
            else:
                retDict = cmd_exec.run(cmd=cmd,expectedcode=expectedcode,raiseOnError=False,lock=lock,outputpaths=outputpaths,env=env)
            t0 = retDict['timing']['t0']
            t1 = retDict['timing']['t1']
            code = retDict['code']
            retout = retDict['retout']
            fileouts = retDict['fileouts']

            # keep trying to communicate with TPM if there was an I/O error
            if code==tpm_abstract.AbstractTPM.TPM_IO_ERR:
                numtries+=1
                maxr = self.config.getint('cloud_agent','max_retries')
                if numtries >= maxr:
                    logger.error("TPM appears to be in use by another application.  Keylime is incompatible with other TPM TSS applications like trousers/tpm-tools. Please uninstall or disable.")
                    break
                retry  = self.config.getfloat('cloud_agent','retry_interval')
                logger.info("Failed to call TPM %d/%d times, trying again in %f seconds..."%(numtries,maxr,retry))
                time.sleep(retry)
                continue
            else:
                break

        # Don't bother continuing if TPM call failed and we're raising on error
        if code!=expectedcode and raiseOnError:
            raise Exception("Command: %s returned %d, expected %d, output %s"%(cmd,code,expectedcode,retout))

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
            #print "\033[95mTIMING: %s%s\t:%f\toutlines:%d\tfilelines:%d\t%s\033[0m" % (fprt,pad,t1-t0,len(retout),filelen,cmd)
            if common.TPM_BENCHMARK_PATH is not None:
                with open(common.TPM_BENCHMARK_PATH, "ab") as bench:
                    bench.write("TIMING: %s%s\ttime:%f\toutlines:%d\tfilecount:%d\t%s\n" % (fprt,pad,t1-t0,len(retout),filelen,cmd))

            # Print out YAML canned values (if requested)
            # NOTE: resulting file will be missing the surrounding braces! (must add '{' and '}' for reading)
            if common.TPM_CANNED_VALUES_PATH is not None:
                with open(common.TPM_CANNED_VALUES_PATH, "ab") as can:
                    fileoutEncoded = ""
                    if outputpaths is not None and len(outputpaths) > 0:
                        if len(fileouts) == 1 and len(outputpaths) == 1:
                            fileoutEncoded = zlib.compress(base64.b64encode(iter(fileouts.values()).next()))
                        else:
                            raise Exception("Command %s is using multiple files unexpectedly!"%(fprt))

                    # tpm_cexec will need to know the nonce
                    nonce = ""
                    match = re.search("-nonce ([\w]+)", cmd)
                    if match:
                        nonce = match.group(1)

                    yamlObj = {'type':fprt,'retout':retout,'fileout':fileoutEncoded,'cmd':cmd,'timing':t1-t0,'code':code,'nonce':nonce}
                    can.write("\"%s\": %s,\n"%(fprt,yaml.dump(yamlObj,indent=4,sort_keys=True, Dumper=SafeDumper)))

        return retDict


    #tpm_initialize
    def __create_ek(self):
        # this function is intended to be idempotent
        retDict = self.__run("createek",raiseOnError=False)
        output = common.list_convert(retDict['retout'])
        code = retDict['code']
        if code!=tpm_abstract.AbstractTPM.EXIT_SUCESS:
            if len(output)>0 and output[0].startswith("Error Target command disabled from TPM_CreateEndorsementKeyPair"):
                logger.debug("TPM EK already created.")
            elif len(output)>0 and output[0].startswith("Error Defend lock running from TPM_CreateEndorsementKeyPair"):
                logger.debug("createek failed.  TPM locked, will attempt unlock during while taking ownership.  To manually repair run resetlockvalue -pwdo [owner_password]")
            else:
                raise Exception("createek failed with code "+str(code)+": "+str(output))
        return

    def __test_ownerpw(self,owner_pw,reentry=False):
        #make a temp file for the output
        with tempfile.NamedTemporaryFile() as tmppath:
            retDict = self.__run("getpubek -pwdo %s -ok %s"%(owner_pw,tmppath.name),raiseOnError=False,outputpaths=tmppath.name)
            output = common.list_convert(retDict['retout'])
            code = retDict['code']
            if code!=tpm_abstract.AbstractTPM.EXIT_SUCESS:
                if len(output)>0 and output[0].startswith("Error Authentication failed (Incorrect Password) from TPM_OwnerReadPubek"):
                    return False
                elif len(output)>0 and output[0].startswith("Error Defend lock running from TPM_OwnerReadPubek"):
                    if reentry:
                        logger.error("Unable to unlock TPM")
                        return False
                    # tpm got locked. lets try to unlock it
                    logger.error("TPM is locked from too many invalid owner password attempts, attempting to unlock with password: %s"%owner_pw)
                    # i have no idea why, but runnig this twice seems to actually work
                    self.__run("resetlockvalue -pwdo %s"%owner_pw,raiseOnError=False)
                    self.__run("resetlockvalue -pwdo %s"%owner_pw,raiseOnError=False)
                    return self.__test_ownerpw(owner_pw,True)
                else:
                    raise Exception("test ownerpw, getpubek failed with code "+str(code)+": "+str(output))
        return True

    def __take_ownership(self,config_pw):
        owner_pw = self.get_tpm_metadata("owner_pw")
        ownerpw_known = False
        if not self.__is_tpm_owned():
            # if no ownerpassword
            if config_pw == 'generate':
                logger.info("Generating random TPM owner password")
                owner_pw = tpm_abstract.TPM_Utilities.random_password(20)
            else:
                logger.info("Taking ownership with config provided TPM owner password: %s"%config_pw)
                owner_pw = config_pw

            logger.info("Taking ownership of TPM")
            self.__run("takeown -pwdo %s -nopubsrk"%owner_pw)
            ownerpw_known = True
        else:
            logger.debug("TPM ownership already taken")


        # tpm owner_pw still not known, and non provided? bail
        if owner_pw is None and config_pw == 'generate':
            raise Exception("TPM is owned, but owner password has not been provided.  Set config option tpm_ownerpassword to the existing password if known.  If not know, TPM reset is required.")

        # now we have owner_pw from tpmdata.yml and a config_pw.
        if not ownerpw_known:
            if owner_pw is None or not self.__test_ownerpw(owner_pw):
                logger.info("TPM Owner password: %s from tpmdata.yml invalid.  Trying config provided TPM owner password: %s"%(owner_pw,config_pw))
                owner_pw = config_pw
                if not self.__test_ownerpw(owner_pw):
                    raise Exception("Config provided owner password %s invalid. Set config option tpm_ownerpassword to the existing password if known.  If not know, TPM reset is required."%owner_pw)
            ownerpw_known = True

        self._set_tpm_metadata('owner_pw',owner_pw)

        if not ownerpw_known:
            raise Exception("Owner password unknown, TPM reset required")
        else:
            logger.info("TPM Owner password confirmed: %s"%owner_pw)

    def __get_pub_ek(self): # assumes that owner_pw is correct at this point
        owner_pw = self.get_tpm_metadata('owner_pw')
        #make a temp file for the output
        with tempfile.NamedTemporaryFile() as tmppath:
            retDict = self.__run("getpubek -pwdo %s -ok %s"%(owner_pw,tmppath.name),raiseOnError=False,outputpaths=tmppath.name) # generates pubek.pem
            output = common.list_convert(retDict['retout'])
            code = retDict['code']
            ek = retDict['fileouts'][tmppath.name]
            if code!=tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("getpubek failed with code "+str(code)+": "+str(output))

        self._set_tpm_metadata('ek',ek)

    def __create_aik(self,activate):
        # if no AIK created, then create one
        if self.get_tpm_metadata('aik') is not None and self.get_tpm_metadata('aikpriv') is not None and self.get_tpm_metadata('aikmod') is not None:
            logger.debug("AIK already created")
        else:
            logger.debug("Creating a new AIK identity")
            extra = ""
            if activate:
                extra = "-ac"

            owner_pw = self.get_tpm_metadata('owner_pw')
            aik_pw = tpm_abstract.TPM_Utilities.random_password(20)
            #make a temp file for the output
            with tempfile.NamedTemporaryFile() as tmppath:
                retDict = self.__run("identity -la aik -ok %s -pwdo %s -pwdk %s %s"%(tmppath.name,owner_pw,aik_pw,extra),outputpaths=tmppath.name)
                retout = common.list_convert(retDict['retout'])
                code = retDict['code']
                fileout = retDict['fileouts'][tmppath.name]
                inPem=False
                pem=""
                for line in retout:
                    if line.startswith("-----BEGIN PUBLIC KEY-----"):
                        inPem=True
                    if inPem:
                        pem+=line
                    if line.startswith("-----END PUBLIC KEY-----"):
                        inPem=False
                if pem=="":
                    raise Exception("unable to read public aik from create identity.  Is your tpm4720 installation up to date?")
                mod = self.__get_mod_from_pem(pem)
                # read in the output
                if fileout=='':
                    raise Exception("unable to read file output.  Is your tpm4720 installation up to date?")
                key = base64.b64encode(fileout)

                # persist results
                self._set_tpm_metadata('aik',pem)
                self._set_tpm_metadata('aikpriv', key)
                self._set_tpm_metadata('aikmod',mod)
                self._set_tpm_metadata('aik_pw',aik_pw)
            if activate:
                logger.debug("Self-activated AIK identity in test mode")

        # ensure the AIK is loaded
        handle = self.__load_aik()
        self._set_tpm_metadata('aik_handle', handle)

    def flush_keys(self):
        logger.debug("Flushing keys from TPM...")
        retDict = self.__run("listkeys")
        retout = retDict['retout']
        for line in retout:
            tokens = line.split()
            if len(tokens)==4 and tokens[0]=='Key' and tokens[1]=='handle':
                handle = tokens[3].upper()
                #logger.debug("Flushing key handle %s"%handle)
                self.__run("flushspecific -ha %s -rt 1"%handle)

    def __load_aik(self):
        logger.debug("Loading AIK private key into TPM")

        # write out private key
        with tempfile.NamedTemporaryFile() as inFile:
            inFile.write(base64.b64decode(self.get_tpm_metadata('aikpriv')))
            inFile.flush()

            retDict = self.__run("loadkey -hp 40000000 -ik %s"%(inFile.name))
            retout = retDict['retout']

            if len(retout)>0 and len(retout[0].split())>=4:
                handle = retout[0].split()[4]
            else:
                raise Exception("unable to process output of loadkey %s"%(retout))

        return handle.upper().decode('utf-8')

    def encryptAIK(self,uuid,pubaik,pubek,ek_tpm,aik_name):
        pubaikFile=None
        pubekFile=None
        keyblob = None
        blobpath = None
        keypath = None

        try:
            # write out pubaik
            pfd, ptemp = tempfile.mkstemp()
            pubaikFile = open(ptemp,"wb")
            pubaikFile.write(pubaik.encode('utf-8'))
            pubaikFile.close()
            os.close(pfd)

            # write out the public EK
            efd, etemp = tempfile.mkstemp()
            pubekFile = open(etemp,"wb")
            pubekFile.write(pubek.encode('utf-8'))
            pubekFile.close()
            os.close(efd)

            #create temp files for the blob
            blobfd,blobpath = tempfile.mkstemp()
            keyfd,keypath = tempfile.mkstemp()

            self.__run("encaik -ik %s -ek %s -ok %s -oak %s"%(pubaikFile.name,pubekFile.name,blobpath,keypath),lock=False)

            logger.info("Encrypting AIK for UUID %s"%uuid)

            # read in the blob
            f = open(blobpath,"rb")
            keyblob = base64.b64encode(f.read())
            f.close()
            os.close(blobfd)

            # read in the aes key
            f = open(keypath,"rb")
            key = base64.b64encode(f.read())
            f.close()
            os.close(keyfd)

        except Exception as e:
            logger.error("Error encrypting AIK: "+str(e))
            logger.exception(e)
            return False
        finally:
            if pubaikFile is not None:
                os.remove(pubaikFile.name)
            if pubekFile is not None:
                os.remove(pubekFile.name)
            if blobpath is not None:
                os.remove(blobpath)
            if keypath is not None:
                os.remove(keypath)
            pass
        return (keyblob,key)


    def activate_identity(self,keyblob):
        owner_pw = self.get_tpm_metadata('owner_pw')
        keyhandle = self.get_tpm_metadata('aik_handle')

        keyblobFile = None
        secpath = None
        try:
            # write out key blob
            kfd, ktemp = tempfile.mkstemp()
            keyblobFile = open(ktemp,"wb")
            keyblobFile.write(base64.b64decode(keyblob))
            keyblobFile.close()
            os.close(kfd)

            # ok lets write out the key now
            secdir=secure_mount.mount() # confirm that storage is still securely mounted

            secfd,secpath=tempfile.mkstemp(dir=secdir)

            command = "activateidentity -hk %s -pwdo %s -pwdk %s -if %s -ok %s"%(keyhandle,owner_pw,self.get_tpm_metadata('aik_pw'),keyblobFile.name,secpath)
            retDict = self.__run(command,outputpaths=secpath)
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
            return None
        finally:
            if keyblobFile is not None:
                os.remove(keyblobFile.name)
            if secpath is not None and os.path.exists(secpath):
                os.remove(secpath)
        return key

    def verify_ek(self,ekcert,ekpem):
        """Verify that the provided EK certificate is signed by a trusted root
        :param ekcert: The Endorsement Key certificate in DER format
        :param ekpem: the endorsement public key in PEM format
        :returns: True if the certificate can be verified, false otherwise
        """
        #openssl x509 -inform der -in certificate.cer -out certificate.pem
        try:
            pubekmod = base64.b64decode(self.__get_mod_from_pem(ekpem))

            ek509 = M2Crypto.X509.load_cert_der_string(ekcert)

            # locate the region where the pub ek should be and then brute force looking for it.  this is awful!
            # Sadly TPM ek certificates are corrupted in a way that openssl and most other utilities can't read them.
            # sigh TCG
            #
            # search for first 1.2.840.113549.1.1.5 (OID for sha1WithRSAEncryption (PKCS #1))
            start = ekcert.index(codecs.decode('2a864886f70d010107','hex_codec'))
            # now locate the next 1.2.840.113549.1.1.7 (OID for rsaOAEP (PKCS #1)) afterwards
            end = ekcert.index(codecs.decode('2a864886f70d010105','hex_codec'))

            if str(pubekmod) not in str(ekcert[start:end]):
                logger.error("Public EK does not match EK certificate")
                return False

            for signer in tpm_ek_ca.trusted_certs:
                signcert = M2Crypto.X509.load_cert_string(tpm_ek_ca.trusted_certs[signer])
                signkey = signcert.get_pubkey()
                if ek509.verify(signkey) == 1:
                    logger.debug("EK cert matched signer %s"%signer)
                    return True

            for key in tpm_ek_ca.atmel_trusted_keys:
                e = m2.bn_to_mpi(m2.hex_to_bn(tpm_ek_ca.atmel_trusted_keys[key]['exponent']))
                n = m2.bn_to_mpi(m2.hex_to_bn(tpm_ek_ca.atmel_trusted_keys[key]['key']))
                rsa = M2Crypto.RSA.new_pub_key((e, n))
                pubkey = M2Crypto.EVP.PKey()
                pubkey.assign_rsa(rsa)

                if ek509.verify(pubkey) == 1:
                    logger.debug("EK cert matched trusted key %s"%key)
                    return True
        except Exception as e:
            # Log the exception so we don't lose the raw message
            logger.exception(e)
            raise Exception("Error processing ek/ekcert. Does this TPM have a valid EK?").with_traceback(sys.exc_info()[2])

        logger.error("No Root CA matched EK Certificate")
        return False

    def get_tpm_manufacturer(self):
        retDict = self.__run("getcapability -cap 1a")
        retout = retDict['retout']
        for line in retout:
            line = line.decode('utf-8')
            tokens = line.split()
            if len(tokens)== 3 and tokens[0]=='VendorID' and tokens[1]==':':
                #logger.debug("TPM vendor id: %s",tokens[2])
                return tokens[2]
        return None

    def is_emulator(self):
        return 'IBM'==self.get_tpm_manufacturer()

    def is_vtpm(self):
        if common.STUB_VTPM:
            return True
        else:
            return 'ETHZ'==self.get_tpm_manufacturer()

    def __is_tpm_owned(self):
        retDict = self.__run("getcapability -cap 5 -scap 111")
        retout = retDict['retout']
        tokens = retout[0].decode('utf-8').split()
        if tokens[-1]=='TRUE':
            return True
        else:
            return False

    def __get_mod_from_pem(self, pem):
        """ Extract public modulus for the RSA key """
        pubkey_nums = crypto.rsa_import_pubkey(pem).public_numbers()
        return base64.b64encode(bytearray.fromhex('{:0192x}'.format(pubkey_nums.n)))


    def tpm_init(self,self_activate=False,config_pw=None):
        # this was called tpm_initialize.init before
        self.warn_emulator()
        self.__create_ek()
        self.__take_ownership(config_pw)

        self.__get_pub_ek()

        ekcert = self.read_ekcert_nvram()
        self._set_tpm_metadata('ekcert',ekcert)

        # if no AIK created, then create one
        self.__create_aik(self_activate)

        return self.get_tpm_metadata('ek'),self.get_tpm_metadata('ekcert'),self.get_tpm_metadata('aik'),self.get_tpm_metadata('ek_tpm'),self.get_tpm_metadata('aik_name')


    #tpm_quote
    def create_deep_quote(self,nonce,data=None,vpcrmask=tpm_abstract.AbstractTPM.EMPTYMASK,pcrmask=tpm_abstract.AbstractTPM.EMPTYMASK):
        quote = ""
        with tempfile.NamedTemporaryFile() as quotepath:
            # read in the vTPM key handle
            keyhandle = self.get_tpm_metadata('aik_handle')
            owner_pw = self.get_tpm_metadata('owner_pw')
            aik_pw = self.get_tpm_metadata('aik_pw')

            if pcrmask is None:
                pcrmask = tpm_abstract.AbstractTPM.EMPTYMASK
            if vpcrmask is None:
                vpcrmask = tpm_abstract.AbstractTPM.EMPTYMASK

            # need to hold the lock while we reset and extend the pcr and then do the quote
            with self.tpmutilLock:
                if data is not None:
                    # add PCR 16 to pcrmask
                    vpcrmask = "0x%X"%(int(vpcrmask,0) + (1 << common.TPM_DATA_PCR))
                    self.__run("pcrreset -ix %d"%common.TPM_DATA_PCR,lock=False)
                    self.__run("extend -ix %d -ic %s"%(common.TPM_DATA_PCR,hashlib.sha1(data).hexdigest()),lock=False)

                command = "deepquote -vk %s -hm %s -vm %s -nonce %s -pwdo %s -pwdk %s -oq %s" % (keyhandle, pcrmask, vpcrmask, nonce, owner_pw, aik_pw, quotepath.name)
                #print("Executing %s"%(command))
                retDict = self.__run(command,lock=False,outputpaths=quotepath.name)
                retout = retDict['retout']
                code = retDict['code']
                quoteraw = retDict['fileouts'][quotepath.name]
                quote = base64.b64encode(zlib.compress(quoteraw))

        return b'd'+quote

    def create_quote(self,nonce,data=None,pcrmask=tpm_abstract.AbstractTPM.EMPTYMASK,hash_alg=None):
        quote = ""
        with tempfile.NamedTemporaryFile() as quotepath:
            keyhandle = self.get_tpm_metadata('aik_handle')
            aik_pw = self.get_tpm_metadata('aik_pw')

            if pcrmask is None:
                pcrmask = tpm_abstract.AbstractTPM.EMPTYMASK

            with self.tpmutilLock:
                if data is not None:
                    # add PCR 16 to pcrmask
                    pcrmask = "0x%X"%(int(pcrmask,0) + (1 << common.TPM_DATA_PCR))
                    self.__run("pcrreset -ix %d"%common.TPM_DATA_PCR,lock=False)
                    self.__run("extend -ix %d -ic %s"%(common.TPM_DATA_PCR,self.hashdigest(data)),lock=False)

                command = "tpmquote -hk %s -pwdk %s -bm %s -nonce %s -noverify -oq %s"%(keyhandle,aik_pw,pcrmask,nonce,quotepath.name)
                retDict = self.__run(command,lock=False,outputpaths=quotepath.name)
                retout = retDict['retout']
                code = retDict['code']
                quoteraw = retDict['fileouts'][quotepath.name]
                quote = base64.b64encode(zlib.compress(quoteraw))

        return b'r'+quote

    def __checkdeepquote_c(self, hAIK, vAIK, deepquoteFile, nonce):
        os.putenv('TPM_SERVER_PORT', '9999')
        os.putenv('TPM_SERVER_NAME', '9999')
        os.putenv('PATH', os.getenv('PATH') + ':/usr/local/bin')

        if common.STUB_TPM and common.TPM_CANNED_VALUES is not None:
            yamlIn = common.TPM_CANNED_VALUES
            if 'deepquote' in yamlIn:
                # YAML unicode-ifies strings, and C calls require byte strings (str)
                if 'nonce' in yamlIn['deepquote']:
                    nonce = str(yamlIn['deepquote']['nonce'])
            else:
                raise Exception("Could not get deepquote from canned YAML!")

        cmd = 'checkdeepquote -aik {0} -deepquote {1} -nonce {2} -vaik {3}'.format(hAIK, deepquoteFile, nonce, vAIK)
        #logger.info('Running cmd %r', cmd)

        retDict = self.__run(cmd,lock=False)
        return retDict['retout']

    def check_deep_quote(self,nonce,data,quote,vAIK,hAIK,vtpm_policy={},tpm_policy={},ima_measurement_list=None,ima_whitelist={}):
        quoteFile=None
        vAIKFile=None
        hAIKFile=None

        if quote[0]!='d':
            raise Exception("Invalid deep quote type %s"%quote[0])
        quote = quote[1:]

        try:
            # write out quote
            qfd, qtemp = tempfile.mkstemp()
            quoteFile = open(qtemp,"wb")
            quoteFile.write(zlib.decompress(base64.b64decode(quote)))
            quoteFile.close()
            os.close(qfd)

            afd, atemp = tempfile.mkstemp()
            vAIKFile = open(atemp,"w")
            vAIKFile.write(vAIK)
            vAIKFile.close()
            os.close(afd)

            afd, atemp = tempfile.mkstemp()
            hAIKFile = open(atemp,"w")
            hAIKFile.write(hAIK)
            hAIKFile.close()
            os.close(afd)

            retout = self.__checkdeepquote_c(hAIKFile.name, vAIKFile.name, quoteFile.name, nonce)
        except Exception as e:
            logger.error("Error verifying quote: %s"%(e))
            logger.exception(e)
            return False
        finally:
            if vAIKFile is not None:
                os.remove(vAIKFile.name)
            if hAIKFile is not None:
                os.remove(hAIKFile.name)
            if quoteFile is not None:
                os.remove(quoteFile.name)
            pass

        if len(retout)<1:
            return False

        if retout[0]!="Verification against AIK succeeded\n":
            logger.error("Failed to validate signature, output: %s"%retout)
            return False

        pcrs = None
        vpcrs = None
        for line in retout:
            if line=="PCR contents from quote:\n":
                pcrs = []
                continue
            if line=="PCR contents from vTPM quote:\n":
                vpcrs = []
                continue
            if line=="\n":
                continue
            # order important here
            if vpcrs is not None:
                vpcrs.append(line)
            elif pcrs is not None:
                pcrs.append(line)

        # don't pass in data to check pcrs for physical quote
        return self.check_pcrs(tpm_policy,pcrs,None,False,None,None) and self.check_pcrs(vtpm_policy, vpcrs, data, True,ima_measurement_list,ima_whitelist)

    def __check_quote_c(self, aikFile, quoteFile, extData):
        os.putenv('TPM_SERVER_PORT', '9999')
        os.putenv('TPM_SERVER_NAME', '9999')
        os.putenv('PATH', os.getenv('PATH') + ':/usr/local/bin')

        if common.STUB_TPM and common.TPM_CANNED_VALUES is not None:
            yamlIn = common.TPM_CANNED_VALUES
            if 'tpmquote' in yamlIn and 'nonce' in yamlIn['tpmquote']:
                # YAML unicode-ifies strings, and C calls require byte strings (str)
                extData = str(yamlIn['tpmquote']['nonce'])
            else:
                raise Exception("Could not get quote nonce from canned YAML!")

        #print('Executing "%s"' % ("checkquote -aik %s -quote %s -nonce %s"%(aikFile, quoteFile, extData),))
        if common.USE_CLIME:
            import _cLime
            retout = _cLime.checkquote('-aik', aikFile, '-quote', quoteFile, '-nonce', extData)
            retout = [line + '\n' for line in retout.split('\n')]
            # Try and be transparent to tpm_quote.py
            return retout
        else:
            retDict = self.__run("checkquote -aik %s -quote %s -nonce %s"%(aikFile, quoteFile, extData),lock=False)
            return retDict['retout']

    def check_quote(self,nonce,data,quote,aikFromRegistrar,tpm_policy={},ima_measurement_list=None,ima_whitelist={},hash_alg=None):
        quoteFile=None
        aikFile=None

        if quote[0]!='r':
            raise Exception("Invalid quote type %s"%quote[0])
        quote = quote[1:]

        try:
            # write out quote
            qfd, qtemp = tempfile.mkstemp()
            quoteFile = open(qtemp,"wb")

            quoteFile.write(zlib.decompress(base64.b64decode(quote)))
            quoteFile.close()
            os.close(qfd)

            afd, atemp = tempfile.mkstemp()
            aikFile = open(atemp,"w")
            aikFile.write(aikFromRegistrar)
            aikFile.close()
            os.close(afd)

            retout = self.__check_quote_c(aikFile.name, quoteFile.name, nonce)
        except Exception as e:
            logger.error("Error verifying quote: "+str(e))
            logger.exception(e)
            return False
        finally:
            if aikFile is not None:
                os.remove(aikFile.name)
            if quoteFile is not None:
                os.remove(quoteFile.name)
            pass

        if len(retout)<1:
            return False

        if retout[0]!=b"Verification against AIK succeeded\n":
            logger.error("Failed to validate signature, output: %s"%retout)
            return False

        pcrs = None
        for line in retout[1:]:
            if line==b"PCR contents from quote:\n":
                pcrs = []
                continue
            if line==b"\n":
                continue
            if pcrs is not None:
                pcrs.append(line.decode('utf-8'))

        return self.check_pcrs(tpm_policy,pcrs,data,False,ima_measurement_list,ima_whitelist)

    def extendPCR(self,pcrval,hashval,hash_alg=None,lock=True):
        if hash_alg is None:
            hash_alg = self.defaults['hash']

        self.__run("extend -ix %d -ih %s"%(pcrval,hashval))

    def readPCR(self,pcrval,hash_alg=None):
        if hash_alg is None:
            hash_alg = self.defaults['hash']

        output = self.__run("pcrread -ix %s"%pcrval)['retout']
        return output[0].split()[5]


    #tpm_random
    def _get_tpm_rand_block(self,size=4096):
        #make a temp file for the output
        rand=None
        with tempfile.NamedTemporaryFile() as randpath:
            try:
                command = "getrandom -size %d -out %s" % (size,randpath.name)
                retDict = self.__run(command,outputpaths=randpath.name)
                retout = retDict['retout']
                code = retDict['code']
                rand = retDict['fileouts'][randpath.name]
            except Exception as e:
                if not self.tpmrand_warned:
                    logger.warn("TPM randomness not available: %s"%e)
                    self.tpmrand_warned=True
                return []
        return rand


    #tpm_nvram
    def write_key_nvram(self,key):
        owner_pw = self.get_tpm_metadata('owner_pw')

        # write out quote
        with tempfile.NamedTemporaryFile() as keyFile:
            keyFile.write(key)
            keyFile.flush()

            self.__run("nv_definespace -pwdo %s -in 1 -sz %d -pwdd %s -per 40004"%(owner_pw,common.BOOTSTRAP_KEY_SIZE,owner_pw),raiseOnError=False)
            self.__run("nv_writevalue -pwdd %s -in 1 -if %s"%(owner_pw,keyFile.name),raiseOnError=False)
        return

    def read_ekcert_nvram(self):
        #make a temp file for the quote
        with tempfile.NamedTemporaryFile() as nvpath:
            owner_pw = self.get_tpm_metadata('owner_pw')

            retDict = self.__run("nv_readvalue -pwdo %s -in 1000f000 -cert -of %s"%(owner_pw,nvpath.name),raiseOnError=False,outputpaths=nvpath.name)
            output = common.list_convert(retDict['retout'])
            code = retDict['code']
            ekcert = retDict['fileouts'][nvpath.name]

            if code!=tpm_abstract.AbstractTPM.EXIT_SUCESS and len(output)>0 and output[0].startswith("Error Illegal index from NV_ReadValue"):
                logger.warn("No EK certificate found in TPM NVRAM")
                return None
            elif code!=tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("nv_readvalue for ekcert failed with code "+str(code)+": "+str(output))

        return base64.b64encode(ekcert)

    def read_key_nvram(self):
        with tempfile.NamedTemporaryFile() as nvpath:
            owner_pw = self.get_tpm_metadata('owner_pw')

            retDict = self.__run("nv_readvalue -pwdd %s -in 1 -sz %d -of %s"%(owner_pw,common.BOOTSTRAP_KEY_SIZE,nvpath.name),raiseOnError=False,outputpaths=nvpath.name)
            output = common.list_convert(retDict['retout'])
            code = retDict['code']
            key = retDict['fileouts'][nvpath.name]

            if code!=tpm_abstract.AbstractTPM.EXIT_SUCESS and len(output)>0 and (output[0].startswith("Error Illegal index from NV_ReadValue") or output[0].startswith("Error Authentication failed")):
                logger.debug("No stored U in TPM NVRAM")
                return None
            elif code!=tpm_abstract.AbstractTPM.EXIT_SUCESS:
                raise Exception("nv_readvalue failed with code "+str(code)+": "+str(output))

        if len(key)!=common.BOOTSTRAP_KEY_SIZE:
            logger.debug("Invalid key length from NVRAM: %d"%(len(key)))
            return None
        return key
