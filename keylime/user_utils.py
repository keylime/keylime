import grp
import os
import pwd
from typing import Optional, Tuple

from keylime import keylime_logging

# Configure logger
logger = keylime_logging.init_logging("privileges")


def string_to_uidgid(user_and_group: str) -> Tuple[Optional[int], Optional[int]]:
    """Translate the user_and_group string to uid and gid.
    The userandgroup parameter must be a string of the format '<user>[:[<group>]]'
    or '[<user>]:gid'
    User and group can be strings or integers. If no group is given, -1 will be
    returned for gid.
    :raises ValueError: if user or group could not be resolved
    """
    params = user_and_group.split(":")
    if len(params) > 2:
        raise ValueError(
            f"User and group {user_and_group} are in wrong format. Expected <user>[:[<group>]] or [<user>]:group"
        )

    gid = None
    if len(params) == 2 and len(params[1]) > 0:
        if params[1].isnumeric():
            gid = int(params[1])
            if gid < 0:
                raise ValueError(f"User and group {user_and_group} contains an illegal value")
        else:
            try:
                gr = grp.getgrnam(params[1])
                gid = gr.gr_gid
            except KeyError as e:
                raise ValueError(f"Could not resolve group {params[1]}: {e}") from e

    uid = None
    if len(params[0]) > 0:
        if params[0].isnumeric():
            uid = int(params[0])
            if uid < 0:
                raise ValueError(f"User and group {user_and_group} contains an illegal value")
        else:
            try:
                passwd = pwd.getpwnam(params[0])
                uid = passwd.pw_uid
            except KeyError as e:
                raise ValueError(f"Could not resolve user {params[0]}: {e}") from e

    if uid is None and gid is None:
        raise ValueError(
            f"User and group {user_and_group} are in wrong format. Expected <user>[:[<group>]] or [<user>]:group"
        )

    return uid, gid


def change_uidgid(user_and_group: str) -> None:
    """Change uid and gid of the current process.
    The user_and_group parameter must be a string of the format
    '<user>[:[<group>]]' or [<user>]:<group>. User and group can
    be strings or integers.
    :raises ValueError: if user or group could not be resolved
    :raises RuntimeError: if setting gid or uid did not succeed
    """
    uid, gid = string_to_uidgid(user_and_group)

    # First change group and then user
    if gid is not None:
        try:
            os.setgid(gid)
        except (OSError, PermissionError) as e:
            raise RuntimeError(f"Could not set gid to {gid}: {e}") from e

    if uid is not None and gid is not None:
        try:
            passwd = pwd.getpwuid(uid)
            username = passwd.pw_name
        except KeyError as e:
            raise ValueError(f"Could not resolve user {uid}: {e}") from e

        groups = os.getgrouplist(username, gid)
        try:
            os.setgroups(groups)
        except (OSError, PermissionError) as e:
            raise RuntimeError(f"Could not set group list to {groups}: {e}") from e

    if uid is not None:
        try:
            os.setuid(uid)
        except (OSError, PermissionError) as e:
            raise RuntimeError(f"Could not set uid to {uid}: {e}") from e


def chown(path: str, user_and_group: str) -> None:
    """Change ownership on a given file to the new owner described in
    user_and_group string.
    The user_and_group parameter must be a string of the format
    '<user>[:[<group>]]' or [<user>]:<group>. User and group can
    be strings or integers.
    :raises ValueError: if user or group could not be resolved
    """
    uid, gid = string_to_uidgid(user_and_group)
    if uid is None:
        uid = -1
    if gid is None:
        gid = -1

    os.chown(path, uid, gid)
