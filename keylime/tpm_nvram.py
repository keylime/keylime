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

import common
import tpm_exec
import tpm_initialize
import tempfile
import os
import sys
import crypto
import base64

logger = common.init_logging('tpm_nvram')

# this may not be TPM spec compliant
#def clear_key_nvram():
#    tpm_exec.run("nv_definespace -pwdo %s -in 1 -sz 0 -pwdd %s -per 40004"%(owner_pw,owner_pw))

def write_key_nvram(key):
    owner_pw = tpm_initialize.get_tpm_metadata('owner_pw')
    
    # write out quote
    with tempfile.NamedTemporaryFile() as keyFile:
        keyFile.write(key)
        keyFile.flush()
        
        tpm_exec.run("nv_definespace -pwdo %s -in 1 -sz %d -pwdd %s -per 40004"%(owner_pw,common.BOOTSTRAP_KEY_SIZE,owner_pw))
        tpm_exec.run("nv_writevalue -pwdd %s -in 1 -if %s"%(owner_pw,keyFile.name))
    return

def read_ekcert_nvram():
    #make a temp file for the quote 
    with tempfile.NamedTemporaryFile() as nvpath:
        owner_pw = tpm_initialize.get_tpm_metadata('owner_pw')
        
        (output,code,ekcert) = tpm_exec.run("nv_readvalue -pwdo %s -in 1000f000 -cert -of %s"%(owner_pw,nvpath.name),raiseOnError=False,outputpath=nvpath.name)
        
        if code!=tpm_exec.EXIT_SUCESS and len(output)>0 and output[0].startswith("Error Illegal index from NV_ReadValue"):
            logger.warn("No EK certificate found in TPM NVRAM")
            return None
        elif code!=tpm_exec.EXIT_SUCESS:
            raise Exception("nv_readvalue for ekcert failed with code "+str(code)+": "+str(output))
    
    return base64.b64encode(ekcert)

def read_key_nvram():
    with tempfile.NamedTemporaryFile() as nvpath:
        owner_pw = tpm_initialize.get_tpm_metadata('owner_pw')
        
        (output,code,key) = tpm_exec.run("nv_readvalue -pwdd %s -in 1 -sz %d -of %s"%(owner_pw,common.BOOTSTRAP_KEY_SIZE,nvpath.name),raiseOnError=False,outputpath=nvpath.name)
            
        if code!=tpm_exec.EXIT_SUCESS and len(output)>0 and (output[0].startswith("Error Illegal index from NV_ReadValue") or output[0].startswith("Error Authentication failed")):
            logger.debug("No stored U in TPM NVRAM")
            return None
        elif code!=tpm_exec.EXIT_SUCESS:
            raise Exception("nv_readvalue failed with code "+str(code)+": "+str(output))

    if len(key)!=common.BOOTSTRAP_KEY_SIZE:
        logger.debug("Invalid key length from NVRAM: %d"%(len(key)))
        return None
    return key
    
    
def main():
    key = crypto.generate_random_key()
    logger.info("orig key: %s"%(key.encode('hex')))
    
    read_key_nvram()
    
    write_key_nvram(key)
    
    newkey = read_key_nvram()
    logger.info("new  key: %s"%(newkey.encode('hex')))
    
    if newkey == key:
        logger.info('matched')
    else:
        logger.info("no match")
    
    read_ekcert_nvram()
    
    sys.exit()
        
if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
