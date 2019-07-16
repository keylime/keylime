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

runs = 250
test_clime=True

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
    print('Checking quote raw %d times ... '%(runs), end='')
    cmd = "for i in `seq 1 %d`; do checkquote -aik %s -quote %s -nonce %s > /dev/null; done"%(runs,aikFile.name, quoteFile.name, keylime.common.TEST_NONCE)
    
    start = timer()
    proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    proc.wait()
    end = timer()
    c = end - start
    print("DONE")
    
#     while True:
#         line = proc.stdout.readline()
#         if line=="":
#             break
#         print(line)
    print("check_quote(raw): %d runs, total time %f, avg %f ms per run" % (runs,c,c/runs*1000))
except Exception as e:
    logger.exception(e)
finally:
    if aikFile is not None:
        os.remove(aikFile.name)
    if quoteFile is not None:
        os.remove(quoteFile.name)
    pass


print('Checking quote %s times ... '%(runs), end='')
keylime.common.STUB_TPM=True
keylime.common.USE_CLIME=False
setup = 'from __main__ import quote,aik,logger,tpm_policy, check_quote'
c = timeit('check_quote(None, None, quote,aik,logger,tpm_policy)', number=runs, setup=setup)
print('DONE')
print("check_quote: %d runs, total time %f, avg %f ms per run" % (runs,c,c/runs*1000))

if test_clime:
    keylime.common.USE_CLIME=True
    print('Checking quote %s times with cLime... '%(runs), end='')
    setup = 'from __main__ import quote,aik,logger,tpm_policy, check_quote'
    c = timeit('check_quote(None, None, quote,aik,logger,tpm_policy)', number=runs, setup=setup)
    print('DONE')
    print("check_quote(cLime): %d runs, total time %f, avg %f ms per run" % (runs,c,c/runs*1000))


print("\n================================\n\n")

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
     
    print('Checking deep quote raw %d times ... '%(runs), end='')
    cmd = "for i in `seq 1 %d`; do checkdeepquote -aik %s -deepquote %s -nonce %s -vaik %s > /dev/null ; done"%(runs,hAIKFile.name, quoteFile.name, keylime.common.TEST_DQ_NONCE,vAIKFile.name)
    start = timer()
    proc = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    proc.wait()
    end = timer()
    c = end - start
    print("DONE")
    
#     while True:
#         line = proc.stdout.readline()
#         if line=="":
#             break
#         print("="+line)

    print("check_deep_quote (raw): %d runs, total time %f, avg %f ms per run" % (runs,c,c/runs*1000))
             
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


print('Checking deep quote %s times ... '%(runs), end='')
keylime.common.STUB_TPM=True
setup = 'from __main__ import quote,vaik,haik,logger,vtpm_policy,tpm_policy, check_deep_quote'
c = timeit('check_deep_quote(None, None, quote,vaik,haik,logger,vtpm_policy,tpm_policy)', number=runs, setup=setup)
print('DONE')
print("check_deep_quote: %d runs, total time %f, avg %f ms per run" % (runs,c,c/runs*1000))


print("\n================================\n\n")

