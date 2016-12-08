#!/usr/bin/python

'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

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

import string
import os
import tpm_exec
import common
import base64
import tempfile
import traceback
import tpm_random
import secure_mount
import tpm_nvram
import json
import crypto
from tpm_ek_ca import *
import M2Crypto
from M2Crypto import m2

logger = common.init_logging('tpm_initialize')

global_tpmdata = None

def random_password(length=20,useTPM=False):
    if useTPM:
        rand = tpm_random.get_tpm_randomness(length)
    else:
        rand = crypto.generate_random_key(length)
        
    chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    password = ''
    for i in range(length):
        password += chars[ord(rand[i]) % len(chars)]
    return password

def create_ek():
    # this function is intended to be idempotent 
    (output,code) = tpm_exec.run("createek",raiseOnError=False)
    if code!=tpm_exec.EXIT_SUCESS and len(output)>0 and output[0].startswith("Error Target command disabled from TPM_CreateEndorsementKeyPair"):
        logger.debug("TPM EK already created.")
    elif code!=tpm_exec.EXIT_SUCESS:
        raise Exception("createek failed with code "+str(code)+": "+str(output))
    return 

def test_ownerpw(owner_pw):
    tmppath = None
    try:
        #make a temp file for the output 
        _,tmppath = tempfile.mkstemp()
        (output,code) = tpm_exec.run("getpubek -pwdo %s -ok %s"%(owner_pw,tmppath),raiseOnError=False) 
        if code!=tpm_exec.EXIT_SUCESS and len(output)>0 and output[0].startswith("Error Authentication failed (Incorrect Password) from TPM_OwnerReadPubek"):
            return False
        elif code!=tpm_exec.EXIT_SUCESS:
            raise Exception("test ownerpw, getpubek failed with code "+str(code)+": "+str(output))
    finally:
        if tmppath is not None:
            os.remove(tmppath)
    return True

def take_ownership(config_pw):
    owner_pw = get_tpm_metadata("owner_pw")
    
    ownerpw_known = False
    if not is_tpm_owned():
        # if no ownerpassword
        if config_pw == 'generate':
            logger.info("Generating random TPM owner password")
            owner_pw = random_password(20,useTPM=True)
        else:
            logger.info("Taking ownership with config provided TPM owner password: %s"%config_pw)
            owner_pw = config_pw
            
        logger.info("Taking ownership of TPM")
        tpm_exec.run("takeown -pwdo %s -nopubsrk"%owner_pw)
        ownerpw_known = True
    else:
        logger.debug("TPM ownership already taken")
        
    
    # tpm owner_pw still not known, and non provided? bail
    if owner_pw is None and config_pw == 'generate':
        raise Exception("TPM is owned, but owner password has not been provided.  Set config option tpm_ownerpassword to the existing password if known.  If not know, TPM reset is required.")
        
    # now we have owner_pw from tpmdata.json and a config_pw.
    if not ownerpw_known:
        if owner_pw is None or not test_ownerpw(owner_pw):
            logger.info("Owner password: %s from tpmdata.json invalid.  Trying config provided TPM owner password: %s"%(owner_pw,config_pw))
            owner_pw = config_pw
            if not test_ownerpw(owner_pw):
                raise Exception("Config provided owner password %s invalid. Set config option tpm_ownerpassword to the existing password if known.  If not know, TPM reset is required."%owner_pw)
            
    if get_tpm_metadata('owner_pw') is not owner_pw:
        set_tpm_metadata('owner_pw',owner_pw)
        
def get_pub_ek(): # assumes that owner_pw is correct at this point
    owner_pw = get_tpm_metadata('owner_pw')
    tmppath = None
    try:
        #make a temp file for the output 
        tmpfd,tmppath = tempfile.mkstemp()
        (output,code) = tpm_exec.run("getpubek -pwdo %s -ok %s"%(owner_pw,tmppath),raiseOnError=False) # generates pubek.pem
        if code!=tpm_exec.EXIT_SUCESS:
            raise Exception("getpubek failed with code "+str(code)+": "+str(output))

        # read in the output
        f = open(tmppath,"rb")
        ek = f.read()
        f.close()
        os.close(tmpfd)
    finally:
        if tmppath is not None:
            os.remove(tmppath)
            
    if get_tpm_metadata('ek') is not ek:
        set_tpm_metadata('ek',ek)

def create_aik(activate):
    # if no AIK created, then create one
    if get_tpm_metadata('aik') is not None and get_tpm_metadata('aikpriv') is not None and get_tpm_metadata('aikmod') is not None:
        logger.debug("AIK already created")
        return
    
    logger.debug("Creating a new AIK identity")
    extra = ""
    if activate:
        extra = "-ac"
    
    owner_pw = get_tpm_metadata('owner_pw')
    tmppath = None
    try:
        #make a temp file for the output 
        tmppath = tempfile.mkstemp()[1]    
        tpm_exec.run("identity -la aik -ok %s -pwdo %s %s"%(tmppath,owner_pw,extra)) 
        # read in the output
        with open(tmppath+".pem","rb") as f:
            pem = f.read()
        mod = get_mod_from_pem(tmppath+'.pem')
        with open(tmppath+".key",'rb') as f:
            key = base64.b64encode(f.read())
    finally:
        if tmppath is not None:
            os.remove(tmppath+".pem")
            os.remove(tmppath+".key")
    if activate:
        logger.debug("Self-activated AIK identity in test mode")

    # persist results
    set_tpm_metadata('aik',pem)
    set_tpm_metadata('aikpriv', key)
    set_tpm_metadata('aikmod',mod)
        
def get_mod_from_pem(pemfile):
    with open(pemfile,"r") as f:
        pem = f.read()
    pubkey = crypto.rsa_import_pubkey(pem)
    return base64.b64encode(bytearray.fromhex('{:0192x}'.format(pubkey.n)))

def get_mod_from_tpm(keyhandle):
    retout = tpm_exec.run("getpubkey -ha %s"%keyhandle)[0]
    # now to parse things!
    inMod = False
    public_modulus = []
    for line in retout:
        if line.startswith("Modulus"):
            inMod = True
            continue
        if inMod:
            tokens = line.split()
            for token in tokens:
                public_modulus.append(string.atol(token,base=16))
    return base64.b64encode(bytearray(public_modulus))
    
def load_aik():
    # is the key already there?
    modFromFile = get_tpm_metadata('aikmod')
    
    retout = tpm_exec.run("listkeys")[0]
    for line in retout:
        tokens = line.split()
        if len(tokens)==4 and tokens[0]=='Key' and tokens[1]=='handle':
            handle = tokens[3]
            modFromTPM = get_mod_from_tpm(handle)
            if modFromTPM == modFromFile:
                #logger.debug("Located AIK at key handle %s"%handle)
                return handle
    
    # we didn't find the key
    logger.debug("Loading AIK private key into TPM")
    
    inFile=None
    try:
        # write out private key
        infd, intemp = tempfile.mkstemp()
        inFile = open(intemp,"wb")
        inFile.write(base64.b64decode(get_tpm_metadata('aikpriv')))
        inFile.close()
        os.close(infd)

        retout = tpm_exec.run("loadkey -hp 40000000 -ik %s"%inFile.name)[0]
        
        if len(retout)>0 and len(retout[0].split())>=4:
            handle = retout[0].split()[4]
        else:
            raise Exception("unable to process output of loadkey %s"%(retout))
    finally:
        if inFile is not None:
            os.remove(inFile.name)
    
    return handle
  
def encryptAIK(uuid,pubaik,pubek):
    pubaikFile=None
    pubekFile=None
    keyblob = None
    blobpath = None
    keypath = None
    
    try:
        # write out pubaik
        pfd, ptemp = tempfile.mkstemp()
        pubaikFile = open(ptemp,"wb")
        pubaikFile.write(pubaik)
        pubaikFile.close()
        os.close(pfd)
        
        # write out the public EK
        efd, etemp = tempfile.mkstemp()
        pubekFile = open(etemp,"wb")
        pubekFile.write(pubek)
        pubekFile.close()
        os.close(efd)
        
        #create temp files for the blob
        blobfd,blobpath = tempfile.mkstemp()
        keyfd,keypath = tempfile.mkstemp()
        
        tpm_exec.run("encaik -ik %s -ek %s -ok %s -oak %s"%(pubaikFile.name,pubekFile.name,blobpath,keypath),lock=False)
        
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
        logger.error(traceback.format_exc())
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

    
def activate_identity(keyblob):
    if common.STUB_TPM:
        return base64.b64encode(common.TEST_AES_REG_KEY)
    
    owner_pw = get_tpm_metadata('owner_pw')
    keyblobFile = None
    secpath = None
    try:
        # write out key blob
        kfd, ktemp = tempfile.mkstemp()
        keyblobFile = open(ktemp,"wb")
        keyblobFile.write(base64.b64decode(keyblob))
        keyblobFile.close()
        os.close(kfd)
        
        keyhandle = load_aik()
        
        keyfd,keypath = tempfile.mkstemp()        
        # read in the key
        f = open(keypath,"rb")
        key = f.read()
        f.close()
        os.close(keyfd)
        
        # ok lets write out the key now
        secdir=secure_mount.mount() # confirm that storage is still securely mounted
            
        secfd,secpath=tempfile.mkstemp(dir=secdir)
        
        tpm_exec.run("activateidentity -hk %s -pwdo %s -if %s -ok %s"%(keyhandle,owner_pw,keyblobFile.name,secpath))
        logger.info("AIK activated.")
        
        f = open(secpath,'rb')
        key = base64.b64encode(f.read())
        f.close()
        os.close(secfd)
        os.remove(secpath)
        
    except Exception as e:
        logger.error("Error decrypting AIK: "+str(e))
        logger.error(traceback.format_exc())
        return False
    finally:
        if keyblobFile is not None:
            os.remove(keyblobFile.name)
        if secpath is not None and os.path.exists(secpath):
            os.remove(secpath)
    return key

#openssl x509 -inform der -in certificate.cer -out certificate.pem
def verify_ek(ekcert,ekpem):
    """Verify that the provided EK certificate is signed by a trusted root
    :param ekcert: The Endorsement Key certificate in DER format
    :param ekpem: the endorsement public key in PEM format
    :returns: True if the certificate can be verified, false otherwise
    """
    tmppath = None
    try:
        # write out key blob
        tmpfd, tmppath = tempfile.mkstemp()
        ekFile = open(tmppath,"wb")
        ekFile.write(ekpem)
        ekFile.close()
        os.close(tmpfd)
        pubekmod = base64.b64decode(get_mod_from_pem(tmppath))
    finally:
        if tmppath is not None:
            os.remove(tmppath)
    
    ek509 = M2Crypto.X509.load_cert_der_string(ekcert)
    
    if str(pubekmod) not in str(ekcert):
        logger.error("Public EK does not match EK certificate")
        return False
    
    for signer in trusted_certs:
        signcert = M2Crypto.X509.load_cert_string(trusted_certs[signer])
        signkey = signcert.get_pubkey()
        if ek509.verify(signkey) == 1:
            logger.debug("EK cert matched signer %s"%signer)
            return True

    for key in atmel_trusted_keys:
        e = m2.bn_to_mpi(m2.hex_to_bn(atmel_trusted_keys[key]['exponent']))
        n = m2.bn_to_mpi(m2.hex_to_bn(atmel_trusted_keys[key]['key']))
        rsa = M2Crypto.RSA.new_pub_key((e, n))
        pubkey = M2Crypto.EVP.PKey()
        pubkey.assign_rsa(rsa)
        if ek509.verify(pubkey) == 1:
            logger.debug("EK cert matched trusted key %s"%key)
            return True
    logger.errror("No Root CA matched EK Certificate")
    return False

def get_tpm_manufacturer():
    retout = tpm_exec.run("getcapability -cap 1a")[0]
    for line in retout:
        tokens = line.split()
        if len(tokens)== 3 and tokens[0]=='VendorID' and tokens[1]==':':
            logger.debug("TPM vendor id: %s",tokens[2])
            return tokens[2]
    return None

def is_vtpm():
    return 'ETHZ'==get_tpm_manufacturer()

def is_tpm_owned():
    retout = tpm_exec.run("getcapability -cap 5 -scap 111")[0]
    tokens = retout[0].split()
    if tokens[-1]=='TRUE':
        return True
    else:
        return False

def read_tpm_data():
    if os.path.exists('tpmdata.json'):
        with open('tpmdata.json','r') as f:
            return json.load(f)
    else:
        return {}
    
def write_tpm_data():
    global global_tpmdata
    with open('tpmdata.json','w') as f:
        json.dump(global_tpmdata,f)

def get_tpm_metadata(key):
    global global_tpmdata
    if global_tpmdata == None:
        global_tpmdata = read_tpm_data()
    return global_tpmdata.get(key,None)

def set_tpm_metadata(key,value):
    global global_tpmdata
    if global_tpmdata == None:
        global_tpmdata = read_tpm_data()
    global_tpmdata[key]=value
    write_tpm_data()

def init(self_activate=False,config_pw=None):
    if not common.STUB_TPM:
        create_ek()
        take_ownership(config_pw)
        
        get_pub_ek()

        ekcert = tpm_nvram.read_ekcert_nvram()
        if get_tpm_metadata('ekcert') is not ekcert:
            set_tpm_metadata('ekcert',ekcert)
        
        # if no AIK created, then create one
        create_aik(self_activate)
        
        # preemptively load AIK up
        load_aik()
        
        return get_tpm_metadata('ek'),get_tpm_metadata('ekcert'),get_tpm_metadata('aik')
    else:
        return common.TEST_PUB_EK,common.TEST_EK_CERT,common.TEST_AIK
    
if __name__=="__main__":
    try:
        init(True,'test')
    except Exception as e:
        logger.exception(e)
