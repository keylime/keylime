'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import os

from keylime import keylime_logging
from keylime import cmd_exec
from keylime import config

logger = keylime_logging.init_logging('secure_mount')


def check_mounted(secdir):
    whatsmounted = cmd_exec.run("mount")['retout']
    whatsmounted_converted = config.list_convert(whatsmounted)
    for line in whatsmounted_converted:
        tokens = line.split()
        tmpfs = False
        if len(tokens) < 3:
            continue
        if tokens[0] == 'tmpfs':
            tmpfs = True
        if tokens[2] == secdir:
            if not tmpfs:
                logger.error("secure storage location %s already mounted on wrong file system type: %s.  Unmount to continue." % (
                    secdir, tokens[0]))
                raise Exception("secure storage location %s already mounted on wrong file system type: %s.  Unmount to continue." % (
                    secdir, tokens[0]))

            logger.debug(
                "secure storage location %s already mounted on tmpfs" % secdir)
            return True
    logger.debug("secure storage location %s not mounted " % secdir)
    return False


def mount():
    secdir = config.WORK_DIR + "/secure"

    if not config.MOUNT_SECURE:
        secdir = config.WORK_DIR + "/tmpfs-dev"
        if not os.path.isdir(secdir):
            os.makedirs(secdir)
        return secdir

    if not check_mounted(secdir):
        # ok now we know it isn't already mounted, go ahead and create and mount
        if not os.path.exists(secdir):
            os.makedirs(secdir, 0o700)
        config.chownroot(secdir, logger)
        size = config.get('cloud_agent', 'secure_size')
        logger.info("mounting secure storage location %s on tmpfs" % secdir)
        cmd = ('mount', '-t', 'tmpfs', '-o', 'size=%s,mode=0700' % size,
               'tmpfs', secdir)
        cmd_exec.run(cmd)

    return secdir
