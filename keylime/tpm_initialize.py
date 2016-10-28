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

def get_pub_ek(ownerpw):
    tmppath = None
    try:
        #make a temp file for the output 
        tmpfd,tmppath = tempfile.mkstemp()
        (output,code) = tpm_exec.run("getpubek -pwdo %s -ok %s"%(ownerpw,tmppath),raiseOnError=False) # generates pubek.pem
        if code!=tpm_exec.EXIT_SUCESS and len(output)>0 and output[0].startswith("Error Authentication failed (Incorrect Password) from TPM_OwnerReadPubek"):
            raise Exception("TPM Owner password invalid, TPM reset required")
        elif code!=tpm_exec.EXIT_SUCESS:
            raise Exception("getpubek failed with code "+str(code)+": "+str(output))

        # read in the output
        f = open(tmppath,"rb")
        output = f.read()
        f.close()
        os.close(tmpfd)
    finally:
        if tmppath is not None:
            os.remove(tmppath)
    
    return output

def take_ownership(config_pw = 'generate'):
    if os.path.isfile("owner_pw.txt"):
        f = open("owner_pw.txt","r")
        ownerpw = f.readline()
        f.close()
        ownerpw = ownerpw.strip()
    else:
        ownerpw = None
    
    if is_tpm_owned():
        logger.debug("TPM ownership already taken")
        return ownerpw,get_pub_ek(ownerpw)
    
    # if no ownerpassword
    if ownerpw is None:
        if config_pw == 'generate':
            logger.info("Generating random TPM owner password")
            ownerpw = random_password(20,useTPM=True)
        else:
            logger.info("Using config provided TPM owner passowrd")
            ownerpw = config_pw
            
        f = open("owner_pw.txt","w")
        f.write(ownerpw)
        f.write('\n')
        f.close()
        
    logger.info("Taking ownership of TPM")
    tpm_exec.run("takeown -pwdo %s -nopubsrk"%ownerpw)

    # check the pub ek with the one in the tpm, get if it doesn't match
    ek = get_pub_ek(ownerpw)
    return ownerpw,ek

def create_aik(owner_pw,activate):
    logger.debug("Creating a new AIK identity")
    extra = ""
    if activate:
        extra = "-ac"
    
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
    
    return pem,key,mod
        
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
    data = get_tpm_data()
    modFromFile = data['aikmod']
    
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
        # write out quote
        infd, intemp = tempfile.mkstemp()
        inFile = open(intemp,"wb")
        inFile.write(base64.b64decode(data['aikpriv']))
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
    
    ownerpw = get_tpm_data()['owner_pw']
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
        
        tpm_exec.run("activateidentity -hk %s -pwdo %s -if %s -ok %s"%(keyhandle,ownerpw,keyblobFile.name,secpath))
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
    
def write_tpm_data(towrite):
    with open('tpmdata.json','w') as f:
        json.dump(towrite,f)
    

def get_tpm_data():
    global global_tpmdata
    if global_tpmdata == None:
        global_tpmdata = read_tpm_data()
    return global_tpmdata

def init(self_activate=False,config_pw=None):
    if not common.STUB_TPM:
        # read in saved state if any
        tpmdata = get_tpm_data()
        
        create_ek()
        owner_pw,ek = take_ownership(config_pw)
        
        if tpmdata.get('owner_pw') is not owner_pw:
            tpmdata['owner_pw'] = owner_pw
            
        if tpmdata.get('ek') is not ek:
            tpmdata['ek'] = ek

        ekcert = tpm_nvram.read_ekcert_nvram()
        if tpmdata.get('ekcert') is not ekcert:
            tpmdata['ekcert'] = ekcert
        
        # if no AIK created, then create one
        if tpmdata.get('aik') is None or tpmdata.get('aikpriv') is None:
            tpmdata['aik'],tpmdata['aikpriv'],tpmdata['aikmod'] = create_aik(owner_pw,self_activate)
        
        # preemptively load AIK
        load_aik()
        write_tpm_data(tpmdata)
        
        return tpmdata['ek'],tpmdata.get('ekcert'),tpmdata['aik']
    else:
        return common.TEST_PUB_EK,common.TEST_EK_CERT,common.TEST_AIK
    
if __name__=="__main__":
    try:
        init(True,'test')
    except Exception as e:
        logger.exception(e)
