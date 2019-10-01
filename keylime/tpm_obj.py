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

import configparser
import distutils.spawn
import os

from keylime import tpm1
from keylime import tpm2
from keylime import common
from keylime import keylime_logging

logger = keylime_logging.init_logging('tpmobj')

# read the config file
config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)

# singleton objects for working with the TPM
__tpm1 = None
__tpm2 = None
__version = None

def __guess_tpm_version():
    if __version is not None:
        return __version

    # Ensure we have paths needed
    env = os.environ.copy()
    env['PATH']=env['PATH']+":%s"%common.TPM_TOOLS_PATH

    # Probe for existence of get capability tools
    has_tpm1_tools = distutils.spawn.find_executable("getcapability", env['PATH']) is not None
    has_tpm2_tools = distutils.spawn.find_executable("tpm2_getcap", env['PATH']) is not None

    if has_tpm1_tools and not has_tpm2_tools:
        return 1
    elif not has_tpm1_tools and has_tpm2_tools:
        return 2
    else:
        # Both toolsets are installed!  See if tpm1 tools work:
        try:
            temp_tpm1 = tpm1.tpm1(True)
            manufacturer = temp_tpm1.get_tpm_manufacturer()
            if isinstance(manufacturer, str):
                return 1
            else:
                return 2
        except Exception as e:
            # Assume tpm2 tools work if tpm1 tools failed
            return 2

# public getter method for the TPM object
def getTPM(need_hw_tpm, tpm_version=None):
    global __tpm1, __tpm2

    # figure out TCG TPM version for this node
    if tpm_version is None:
        if need_hw_tpm:
            tpm_version = __guess_tpm_version()
            __version = tpm_version
        else:
            raise Exception('TPM version must be specified!')

    if tpm_version == 1:
        if __tpm1 is None:
            __tpm1 = tpm1.tpm1(need_hw_tpm)
        return __tpm1
    elif tpm_version == 2:
        if __tpm2 is None:
            __tpm2 = tpm2.tpm2(need_hw_tpm)
        return __tpm2
    else:
        raise Exception('Unsupported TPM version specified: %s!'%(tpm_version))
