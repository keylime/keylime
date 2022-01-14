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
    """Inspect mountinfo to detect if a directory is mounted."""
    secdir_escaped = secdir.replace(" ", r"\040")
    for line in open("/proc/self/mountinfo", "r"):
        # /proc/[pid]/mountinfo have 10+ elements separated with
        # spaces (check proc (5) for a complete description)
        #
        # At position 7 there are some optional fields, so we need
        # first to determine the separator mark, and validate the
        # final total number of fields.
        elements = line.split()
        try:
            separator = elements.index("-")
        except ValueError:
            msg = "Separator filed not found. " \
                "Information line cannot be parsed"
            logger.error(msg)
            raise Exception(msg)

        if len(elements) < 10 or len(elements) - separator < 4:
            msg = "Mount information line cannot be parsed"
            logger.error(msg)
            raise Exception(msg)

        mount_point = elements[4]
        filesystem_type = elements[separator + 1]
        if mount_point == secdir_escaped:
            if filesystem_type != "tmpfs":
                msg = f"Secure storage location {secdir} already mounted " \
                    f"on wrong file system type: {filesystem_type}. " \
                    "Unmount to continue."
                logger.error(msg)
                raise Exception(msg)

            logger.debug(
                "Secure storage location %s already mounted on tmpfs", secdir
            )
            return True

    logger.debug("Secure storage location %s not mounted", secdir)
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
