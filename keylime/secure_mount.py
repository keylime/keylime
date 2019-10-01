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

import os
import configparser

from keylime import cmd_exec
from keylime import common
from keylime import keylime_logging

logger = keylime_logging.init_logging('secure_mount')

# read the config file
config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)

def check_mounted(secdir):
    whatsmounted = cmd_exec.run("mount",lock=False)['retout']
    whatsmounted_converted = common.list_convert(whatsmounted)
    for line in whatsmounted_converted:
        tokens = line.split()
        tmpfs = False
        if len(tokens)<3:
            continue
        if tokens[0]=='tmpfs':
            tmpfs=True
        if tokens[2]==secdir:
            if not tmpfs:
                logger.error("secure storage location %s already mounted on wrong file system type: %s.  Unmount to continue."%(secdir,tokens[0]))
                raise Exception("secure storage location %s already mounted on wrong file system type: %s.  Unmount to continue."%(secdir,tokens[0]))

            logger.debug("secure storage location %s already mounted on tmpfs"%secdir)
            return True
    logger.debug("secure storage location %s not mounted "%secdir)
    return False

def mount():
    secdir = common.WORK_DIR+"/secure"

    if not common.MOUNT_SECURE:
        secdir = common.WORK_DIR+"/tmpfs-dev"
        if not os.path.isdir(secdir):
            os.makedirs(secdir)
        return secdir

    if not check_mounted(secdir):
        # ok now we know it isn't already mounted, go ahead and create and mount
        if not os.path.exists(secdir):
            os.makedirs(secdir,0o700)
        common.chownroot(secdir,logger)
        size = config.get('cloud_agent','secure_size')
        logger.info("mounting secure storage location %s on tmpfs"%secdir)
        cmd_exec.run("mount -t tmpfs -o size=%s,mode=0700 tmpfs %s" %(size,secdir),lock=False)

    return secdir
