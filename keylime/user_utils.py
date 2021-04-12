#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import os
import grp
import pwd

from keylime import keylime_logging

# Configure logger
logger = keylime_logging.init_logging('privileges')


def string_to_uidgid(userandgroup):
    """ Translate the userandgroup string to uid and gid.
        The userandgroup parameter must be a string of the format '<user>[:<group>]'.
        User and group can be strings or integers. If no group is given, -1 will be
        returned for gid.
    """
    params = userandgroup.split(':')
    if len(params) > 2:
        return None, None, "User and group '%s' are in wrong format. Expected <user>[:group]" % userandgroup

    gid = -1
    if len(params) == 2:
        if params[1].isnumeric():
            gid = int(params[1])
        else:
            try:
                gr = grp.getgrnam(params[1])
                gid = gr.gr_gid
            except Exception as e:
                return None, None, 'Could not resolve group %s: %s' % (params[1], str(e))

    if params[0].isnumeric():
        uid = int(params[0])
    else:
        try:
            passwd = pwd.getpwnam(params[0])
            uid = passwd.pw_uid
        except Exception as e:
            return None, None, 'Could not resolve user %s: %s' % (params[0], str(e))

    return uid, gid, None


def change_uidgid(userandgroup):
    """ Change uid and gid of the current process.
        The userandgroup parameter must be a string of the format
        '<user>[:<group>]'. User and group can be strings or integers.
    """
    uid, gid, err = string_to_uidgid(userandgroup)
    if err:
        return err

    # First change group and then user
    if gid >= 0:
        try:
            os.setgid(gid)
        except Exception as e:
            return 'Could not set gid to %d: %s' % (gid, str(e))
    try:
        os.setuid(uid)
    except Exception as e:
        return 'Could not set uid to %d: %s' % (uid, str(e))

    return None


def chown_recursive(path, userandgroup):
    """ Recursively change ownership of all files under rootpath to
        the new owner described in userandgroup string.
        The userandgroup parameter must be a string of the format
        '<user>[:<group>]'. User and group can be strings or integers.
    """
    uid, gid, err = string_to_uidgid(userandgroup)
    if err:
        return err

    for rootpath, _, filenames in os.walk(path):
        os.chown(rootpath, uid, gid, follow_symlinks = False)
        for filename in filenames:
            os.chown(os.path.join(rootpath, filename), uid, gid, follow_symlinks = False)

    return None
