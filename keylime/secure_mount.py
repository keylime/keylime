import os
import shutil
from typing import List

from keylime import cmd_exec, config, keylime_logging

logger = keylime_logging.init_logging("secure_mount")

# Store the mounted directories done by Keylime, so we can unmount
# them in reverse order
_MOUNTED: List[str] = []


def check_mounted(secdir: str) -> bool:
    """Inspect mountinfo to detect if a directory is mounted."""
    secdir_escaped = secdir.replace(" ", r"\040")
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
        # because of tests we use readlines() and avoid using iterator
        # since mocked open cannot use iterator on Python 3.6
        # see https://code-examples.net/en/q/17a1c75
        #     https://bugs.python.org/issue21258
        for line in f.readlines():
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
                msg = "Separator field not found. Information line cannot be parsed"
                logger.error(msg)
                # pylint: disable=raise-missing-from
                raise Exception(msg)

            if len(elements) < 10 or len(elements) - separator < 4:
                msg = "Mount information line cannot be parsed"
                logger.error(msg)
                raise Exception(msg)

            mount_point = elements[4]
            filesystem_type = elements[separator + 1]
            if mount_point == secdir_escaped:
                if filesystem_type != "tmpfs":
                    msg = (
                        f"Secure storage location {secdir} already mounted "
                        f"on wrong file system type: {filesystem_type}. "
                        "Unmount to continue."
                    )
                    logger.error(msg)
                    raise Exception(msg)

                logger.debug("Secure storage location %s already mounted on tmpfs", secdir)
                return True

    logger.debug("Secure storage location %s not mounted", secdir)
    return False


def get_secdir() -> str:
    secdir = os.path.join(config.WORK_DIR, "secure")

    if not config.MOUNT_SECURE:
        secdir = os.path.join(config.WORK_DIR, "tmpfs-dev")

    return secdir


def mount() -> str:
    secdir = get_secdir()

    if not config.MOUNT_SECURE:
        if not os.path.isdir(secdir):
            os.makedirs(secdir)
        return secdir

    if not check_mounted(secdir):
        # ok now we know it isn't already mounted, go ahead and create and mount
        if not os.path.exists(secdir):
            os.makedirs(secdir, 0o700)
        size = config.get("agent", "secure_size")
        logger.info("mounting secure storage location %s on tmpfs", secdir)
        cmd = ("mount", "-t", "tmpfs", "-o", f"size={size},mode=0700", "tmpfs", secdir)
        cmd_exec.run(cmd)
        _MOUNTED.append(secdir)

    return secdir


def umount() -> None:
    """Umount all the devices mounted by Keylime."""

    # Make sure we leave tmpfs dir empty even if we did not mount it or
    # if we cannot unmount it. Ignore errors while deleting. The deletion
    # of the 'secure' directory will result in an error since it's a mount point.
    # Also, with config.MOUNT_SECURE being False we remove the directory
    secdir = get_secdir()
    if not config.MOUNT_SECURE or check_mounted(secdir):
        shutil.rmtree(secdir, ignore_errors=True)

    while _MOUNTED:
        directory = _MOUNTED.pop()
        logger.info("Unmounting %s", directory)
        if check_mounted(directory):
            cmd = ("umount", directory)
            ret = cmd_exec.run(cmd, raiseOnError=False)
            if ret["code"] != 0:
                logger.error(
                    "%s cannot be umounted. A running process can be keeping it bussy: %s",
                    directory,
                    str(ret["reterr"]),
                )
        else:
            logger.warning("%s already unmounted by another process", directory)
