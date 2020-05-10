#!/usr/bin/env python

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

import keylime.common
keylime.common.USE_CLIME=True
from keylime.tpm_quote import check_deep_quote, check_quote
from timeit import timeit
from timeit import default_timer as timer
import logging
import sys
import os
import tempfile
import subprocess
import base64

logging.basicConfig(stream=sys.stdout, level=logging.WARN,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('test_check_quote')

runs = 10000

tpm_policy = {'22':'ffffffffffffffffffffffffffffffffffffffff','16':'0000000000000000000000000000000000000000'}
quote = keylime.common.TEST_QUOTE
aik=keylime.common.TEST_AIK

# now do it raw
try:
    # write out quote
    qfd, qtemp = tempfile.mkstemp()
    quoteFile = open(qtemp,"wb")
 
    quoteFile.write(base64.b64decode(quote).decode("zlib"))
    quoteFile.close()
    os.close(qfd)
 
    afd, atemp = tempfile.mkstemp()
    aikFile = open(atemp,"w")
    aikFile.write(aik)
    aikFile.close()
    os.close(afd)
    print('Checking signature raw %d times ... '%(runs), end='')
    cmd = "checkquote -aik %s -quote %s -nonce %s -repeat %d > /dev/null"%(aikFile.name, quoteFile.name, keylime.common.TEST_NONCE,runs)
    
    start = timer()
    proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    proc.wait()
    end = timer()
    c = end - start
    print("DONE")
    
    while True:
        line = proc.stdout.readline()
        if line=="":
            break
        print("=output="+line)
    print("check_quote (raw sig): %d runs, total time %f, avg %f us per run" % (runs,c,c/runs*1000*1000))
except Exception as e:
    logger.exception(e)
finally:
    if aikFile is not None:
        os.remove(aikFile.name)
    if quoteFile is not None:
        os.remove(quoteFile.name)
    pass

print("\n================================\n")

keylime.common.USE_CLIME=True
tpm_policy = {'22':'ffffffffffffffffffffffffffffffffffffffff','16':'0000000000000000000000000000000000000000'}
vtpm_policy = {'23':'0000000000000000000000000000000000000000','16':'0000000000000000000000000000000000000000'}
quote = keylime.common.TEST_DQ
vaik=keylime.common.TEST_VAIK
haik=keylime.common.TEST_HAIK


# now do it raw
try:
    # write out quote
    qfd, qtemp = tempfile.mkstemp()
    quoteFile = open(qtemp,"wb")
    quoteFile.write(base64.b64decode(quote).decode("zlib"))
    quoteFile.close()
    os.close(qfd)
 
    afd, atemp = tempfile.mkstemp()
    vAIKFile = open(atemp,"w")
    vAIKFile.write(vaik)
    vAIKFile.close()
    os.close(afd)
     
    afd, atemp = tempfile.mkstemp()
    hAIKFile = open(atemp,"w")
    hAIKFile.write(haik)
    hAIKFile.close()
    os.close(afd)
     
    print('Checking deep quote signature %d times ... '%(runs), end='')
    cmd = "checkdeepquote -aik %s -deepquote %s -nonce %s -vaik %s -repeat %d > /dev/null"%(hAIKFile.name, quoteFile.name, keylime.common.TEST_DQ_NONCE,vAIKFile.name,runs)
    start = timer()
    proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    proc.wait()
    end = timer()
    c = end - start
    print("DONE")
    
    while True:
        line = proc.stdout.readline()
        if line=="":
            break
        print("=output="+line)

    print("check_deep_quote (raw sig): %d runs, total time %f, avg %f us per run" % (runs,c,c/runs*1000*1000))
             
except Exception as e:
    logger.exception(e)
finally:
    if vAIKFile is not None:
        os.remove(vAIKFile.name)
    if hAIKFile is not None:
        os.remove(hAIKFile.name)
    if quoteFile is not None:
        os.remove(quoteFile.name)
    pass

print("\n================================\n")

