'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
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
            proc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            code = proc.wait()
    else:
        proc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
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

    # Gather subprocess stderr data
    reterr = []
    while True:
        line = proc.stderr.readline()
        if line==b'':
            break
        reterr.append(line)

    # Don't bother continuing if call failed and we're raising on error
    if code!=expectedcode and raiseOnError:
        raise Exception("Command: %s returned %d, expected %d, output %s, stderr %s"%(cmd,code,expectedcode,retout,reterr))

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
        'reterr': reterr,
        'code': code,
        'fileouts': fileouts,
        'timing': timing,
    }
    return returnDict
