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

import sys
import os
import tpm_exec
import common
import tempfile
import crypto
import fcntl
import struct

logger = common.init_logging('tpm_random')

randomness =""
warned=False

def get_tpm_rand_block(size=4096):
    global warned
    #make a temp file for the output 
    rand=None
    with tempfile.NamedTemporaryFile() as randpath:
        try:
            command = "getrandom -size %d -out %s" % (size,randpath.name)
            (retout,code,rand) = tpm_exec.run(command,outputpath=randpath.name)
        except Exception as e:
            if not warned:
                logger.warn("TPM randomness not available: %s"%e)
                warned=True
            return []
    return rand

def get_tpm_randomness(size=32):
    global randomness
    if size==0:
        return ""
    
    sysrand = crypto.generate_random_key(size)
    
    tpmrand=""
    while size>len(randomness):
        # need moar randomness
        extra = get_tpm_rand_block()
        if extra==[]:
            break
        randomness+=extra
        continue
    
    if size<=len(randomness):
        tpmrand= randomness[:size]
        randomness=randomness[size:]
    
    if len(tpmrand)==len(sysrand):
        return str(crypto.strbitxor(sysrand,str(tpmrand)))
    else:
        return str(sysrand)
    
def init_system_rand():
    RNDADDENTROPY=0x40085203
    rand_data = get_tpm_rand_block(128)
    t = struct.pack("ii%ds"%len(rand_data), 8, len(rand_data), str(rand_data))
    if common.REQUIRE_ROOT:
        try:
            with open("/dev/random", mode='wb') as fp:
                # as fp has a method fileno(), you can pass it to ioctl
                fcntl.ioctl(fp, RNDADDENTROPY, t)
        except Exception as e:
            logger.warn("TPM randomness not added to system entropy pool: %s"%e)
    

def main(argv=sys.argv):
    global randomness
    print "rand test"
    init_system_rand()
    sys.exit(0)
    print "getting big random"
    get_tpm_randomness(1000000)
    print "len randomness %d"%len(randomness)
      
    for i in range(4500):
        print "%d\t\t%d"%(i,len(randomness))
        get_tpm_randomness(i)
        


if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
