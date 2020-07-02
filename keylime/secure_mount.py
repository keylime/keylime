'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import os

from keylime import cmd_exec
from keylime import common
from keylime import keylime_logging

logger = keylime_logging.init_logging('secure_mount')

# read the config file
config = common.get_config()


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
