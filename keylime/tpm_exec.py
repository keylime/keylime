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

# shared lock to serialize access to TPM tools
tpmutilLock = threading.Lock()

EXIT_SUCESS=0

def run(cmd,expectedcode=EXIT_SUCESS,raiseOnError=True,lock=True):
    global tpmutilLock
    env = os.environ.copy()
    env['TPM_SERVER_PORT']='9998'
    env['TPM_SERVER_NAME']='localhost'
    env['PATH']=env['PATH']+":%s"%common.TPM_TOOLS_PATH
    
    if lock:
        with tpmutilLock:
            proc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            code = proc.wait()
    else:
        proc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        code = proc.wait()

    retout = []
    while True:
        line = proc.stdout.readline()
        if line=="":
            break
        retout.append(line)
    
    if code!=expectedcode and raiseOnError:
        raise Exception("Command: %s returned %d, expected %d, output %s"%(cmd,code,expectedcode,retout))
         
    return (retout,code)