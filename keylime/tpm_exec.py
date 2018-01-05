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

import os
import subprocess
import threading
import common
import time

import base64
import ConfigParser
import json
import re

logger = common.init_logging('tpm_exec')

# read the config file
config = ConfigParser.RawConfigParser()
config.read(common.CONFIG_FILE)

# shared lock to serialize access to TPM tools
tpmutilLock = threading.Lock()

EXIT_SUCESS=0
TPM_IO_ERR=5

# Creates a unique-enough ID from the given command 
def fingerprint(cmd):
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

def run(cmd,expectedcode=EXIT_SUCESS,raiseOnError=True,lock=True,outputpath=None):
    global tpmutilLock
    env = os.environ.copy()
    env['TPM_SERVER_PORT']='9998'
    env['TPM_SERVER_NAME']='localhost'
    env['PATH']=env['PATH']+":%s"%common.TPM_TOOLS_PATH

    # Handle stubbing the TPM out
    fprt = fingerprint(cmd)
    if common.STUB_TPM and common.TPM_CANNED_VALUES is not None:
        # Use canned values for stubbing 
        jsonIn = common.TPM_CANNED_VALUES
        if fprt in jsonIn:
            # The value we're looking for has been canned! 
            thisTiming = jsonIn[fprt]['timing']
            thisRetout = jsonIn[fprt]['retout']
            thisCode = jsonIn[fprt]['code']
            thisFileout = jsonIn[fprt]['fileout']
            if thisFileout != '':
                # Decode if it is supplied 
                thisFileout = base64.b64decode(thisFileout).decode("zlib")
            logger.debug("TPM call '%s' was stubbed out, with a simulated delay of %f sec"%(fprt,thisTiming))
            time.sleep(thisTiming)
            return (thisRetout,thisCode,thisFileout)
        elif not lock:
            # non-lock calls don't go to the TPM (just let it pass through) 
            pass
        else:
            # Our command hasn't been canned!
            raise Exception("Command %s not found in canned JSON!"%(fprt))

    numtries = 0
    while True:
        t0 = time.time()
        if lock:
            with tpmutilLock:
                proc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                code = proc.wait()
        else:
            proc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            code = proc.wait()
        t1 = time.time()

        # keep trying to communicate with TPM if there was an I/O error 
        if code==TPM_IO_ERR:
            numtries+=1
            maxr = config.getint('cloud_node','max_retries')
            if numtries >= maxr:
                logger.error("Quitting after max number of retries to call TPM")
                break
            retry  = config.getfloat('cloud_node','retry_interval')
            logger.info("Failed to call TPM %d/%d times, trying again in %f seconds..."%(numtries,maxr,retry))
            time.sleep(retry)
            continue
        else:
            break

    # Gather subprocess response data 
    retout = []
    while True:
        line = proc.stdout.readline()
        if line=="":
            break
        retout.append(line)

    # Don't bother continuing if TPM call failed and we're raising on error 
    if code!=expectedcode and raiseOnError:
        raise Exception("Command: %s returned %d, expected %d, output %s"%(cmd,code,expectedcode,retout))

    # Prepare to return their file contents (if requested)
    fileout=None
    if outputpath is not None:
        with open(outputpath, "rb") as f:
            fileout = f.read()

    # Metric output 
    if lock or tpmutilLock.locked():
        pad = ""
        if len(fprt) < 8:
            pad += "\t"
        if len(fprt) < 16:
            pad += "\t"
        if len(fprt) < 24:
            pad += "\t"

        filelen = 0
        if fileout is not None:
            filelen = len(fileout)

        # Print out benchmarking information for TPM (if requested) 
        #print "\033[95mTIMING: %s%s\t:%f\toutlines:%d\tfilelines:%d\t%s\033[0m" % (fprt,pad,t1-t0,len(retout),filelen,cmd)
        if common.TPM_BENCHMARK_PATH is not None:
            with open(common.TPM_BENCHMARK_PATH, "ab") as f:
                f.write("TIMING: %s%s\t:%f\toutlines:%d\tfilelines:%d\t%s\n" % (fprt,pad,t1-t0,len(retout),filelen,cmd))

        # Print out JSON canned values (if requested)
        # NOTE: resulting file will be missing the surrounding braces! (must add '{' and '}' for reading)
        if common.TPM_CANNED_VALUES_PATH is not None:
            with open(common.TPM_CANNED_VALUES_PATH, "ab") as can:
                fileoutEncode = ""
                if fileout is not None:
                    fileoutEncode = base64.b64encode(fileout.encode("zlib"))

                # tpm_cexec will need to know the nonce 
                nonce = ""
                match = re.search("-nonce ([\w]+)", cmd)
                if match:
                    nonce = match.group(1)

                jsonObj = {'type':fprt,'retout':retout,'fileout':fileoutEncode,'cmd':cmd,'timing':t1-t0,'code':code,'nonce':nonce}
                can.write("\"%s\": %s,\n"%(fprt,json.dumps(jsonObj,indent=4,sort_keys=True)))

    return (retout,code,fileout)
