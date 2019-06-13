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
import time

# shared lock to serialize access to tools
utilLock = threading.Lock()

EXIT_SUCESS=0


def run(cmd,expectedcode=EXIT_SUCESS,raiseOnError=True,lock=True,outputpaths=None,env=os.environ):
    global utilLock

    t0 = time.time()
    if lock:
        with utilLock:
            proc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            code = proc.wait()
    else:
        proc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        code = proc.wait()
    t1 = time.time()
    timing = {'t1': t1, 't0': t0}


    # Gather subprocess response data
    retout = []
    while True:
        line = proc.stdout.readline()
        if line==b'':
            break
        retout.append(line)

    # Don't bother continuing if call failed and we're raising on error
    if code!=expectedcode and raiseOnError:
        raise Exception("Command: %s returned %d, expected %d, output %s"%(cmd,code,expectedcode,retout))

    # Prepare to return their file contents (if requested)
    fileouts={}
    if isinstance(outputpaths, str):
        outputpaths = [outputpaths]
    if isinstance(outputpaths, list):
        for thispath in outputpaths:
            with open(thispath, "rb") as f:
                fileouts[thispath] = f.read()

    returnDict = {
        'retout': retout,
        'code': code,
        'fileouts': fileouts,
        'timing': timing,
    }
    return returnDict
