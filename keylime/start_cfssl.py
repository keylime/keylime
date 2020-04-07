import subprocess
import sys
import os
import shutil
import time
import shlex
from keylime import  keylime_logging

logger = keylime_logging.init_logging('start_cfssl')

def main(cmdline=sys.argv):
    if shutil.which("cfssl") is None:
        logger.error("cfssl binary not found in the path.  Please install cfssl or change the setting \"ca_implementation\" in keylime.conf")
        print("cfssl binary not found in the path.  Please install cfssl or change the setting \"ca_implementation\" in keylime.conf")
        sys.exit(1)

    if len(cmdline) > 1:
        cmdline = shlex.quote(cmdline)
        cmd = "cfssl serve -loglevel=1 %s "%cmdline[1:]
    else:
        cmd = "cfssl serve -loglevel=1"

    env = os.environ.copy()
    env['PATH']=env['PATH']+":/usr/local/bin"
    cmd = shlex.split(cmd)
    cfsslproc = subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True)
    if cfsslproc.returncode is not None:
        raise Exception("Unable to launch %: failed with code "%(cmd,cfsslproc.returncode))

    logger.debug("Waiting for cfssl to start...")
    while True:
        line = cfsslproc.stdout.readline()
        if(line != ""):
            print(line.rstrip())

        if "Now listening on" in line:
            time.sleep(0.2)# give cfssl a little more time to get started
            logger.debug("cfssl started successfully")
            print("cfssl started successfully")
            break

        if "bind: address already in use" in line:
            logger.debug("cfssl could not start. bind already in use")
            print("cfssl could not start. bind already in use")
            break


