'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''
import os
import os.path
import configparser
from typing import Optional

# resources in importlib is a Python 3.7 feature, so we disable
# fallback support if we cannot import this module
try:
    from importlib import resources
    _CONFIG_FALLBACK = True
except ImportError:
    _CONFIG_FALLBACK = False

import yaml
try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader
from yaml.reader import ReaderError


def convert(data):
    if isinstance(data, bytes):
        return data.decode()
    if isinstance(data, dict):
        return dict(map(convert, data.items()))
    if isinstance(data, tuple):
        return tuple(map(convert, data))
    if isinstance(data, list):
        return list(map(convert, data))
    return data


def environ_bool(env_name, default):
    val = os.getenv(env_name, 'default').lower()
    if val in ["on", "true", "1"]:
        return True
    if val in ["off", "false", "0"]:
        return False
    if val == "default":
        return default
    raise ValueError(
        f"Environment variable {env_name} set to invalid value "
        f"{val} (use either on/true/1 or off/false/0)")


# enable printing of keys and other info for debug purposes
INSECURE_DEBUG = False

# allow the emuatlor to not have an ekcert even if check ekcert is true
DISABLE_EK_CERT_CHECK_EMULATOR = False

# whether to use tpmfs or not
MOUNT_SECURE = True

DEFAULT_WORK_DIR = '/var/lib/keylime'
WORK_DIR = os.getenv('KEYLIME_DIR', DEFAULT_WORK_DIR)

# allow testing mode
TEST_MODE = environ_bool('KEYLIME_TEST', False)
if TEST_MODE:
    print("WARNING: running keylime in testing mode.\nKeylime will:\n"
          "- Not check the ekcert for the TPM emulator\n"
          "- Not create a secure mount\n"
          "- Change the KEYLIME_DIR to CWD")
    DISABLE_EK_CERT_CHECK_EMULATOR = True
    MOUNT_SECURE = False
    WORK_DIR = os.getcwd()

# Config files can be merged together, reading from the system to the
# user.
CONFIG_FILES = [
    "/usr/etc/keylime.conf", "/etc/keylime.conf", os.path.expanduser("~/.config/keylime.conf")
]
if "KEYLIME_CONFIG" in os.environ:
    CONFIG_FILES.insert(0, os.environ["KEYLIME_CONFIG"])


def get_config() -> configparser.RawConfigParser:
    """Read configuration files and merge them together."""
    if not getattr(get_config, "config", None):
        # Use RawConfigParser, so we can also use it as the logging config
        config = configparser.RawConfigParser()
        # TODO - use logger and be sure that all variables have a
        # propper default, and the sections are initialized
        if not any(os.path.exists(c) for c in CONFIG_FILES):
            print(f"Config file not found in {CONFIG_FILES}. Please set "
                  f"environment variable KEYLIME_CONFIG or see {__file__} "
                  "for more details.")
            if _CONFIG_FALLBACK:
                print("Falling back on package provided configuration")
                file = resources.files(__package__).joinpath("keylime.conf")
                config.read_string(file.read_text("utf-8"))
        else:
            # Validate that at least one config file is present
            config_files = config.read(CONFIG_FILES)
            # TODO - use the logger
            print(f"Reading configuration from {config_files}")
        get_config.config = config
    return get_config.config


# Re-export some utility functions
get = get_config().get
getint = get_config().getint
getboolean = get_config().getboolean
getfloat = get_config().getfloat
has_option = get_config().has_option

CA_WORK_DIR = f'{WORK_DIR}/ca/'


def yaml_to_dict(arry, add_newlines=True, logger=None) -> Optional[dict]:
    arry = convert(arry)
    sep = "\n" if add_newlines else ""
    try:
        return yaml.load(sep.join(arry), Loader=SafeLoader)
    except ReaderError as err:
        if logger is not None:
            logger.warning("Could not load yaml as dict: %s", str(err))
    return None


IMA_ML = '/sys/kernel/security/ima/ascii_runtime_measurements'

IMA_PCR = 10

# measured boot addons
# PCRs 0-7: BIOS & UEFI
# PCRs 8-9: bootloader (grub)
# PCR 14: MokList, MokListX, and MokSBState
MEASUREDBOOT_PCRS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15]
MEASUREDBOOT_ML = '/sys/kernel/security/tpm0/binary_bios_measurements'
MEASUREDBOOT_IMPORTS = get_config().get('cloud_verifier', 'measured_boot_imports', fallback='').split(',')
MEASUREDBOOT_POLICYNAME = get_config().get('cloud_verifier', 'measured_boot_policy_name', fallback='accept-all')

LIBEFIVAR="libefivar.so" # formerly "/usr/lib/x86_64-linux-gnu/libefivar.so"

# this is where data will be bound to a quote, MUST BE RESETABLE!
TPM_DATA_PCR = 16

# the size of the bootstrap key for AES-GCM 256bit
BOOTSTRAP_KEY_SIZE = 32

# choose between cfssl or openssl for creating CA certificates
CA_IMPL = get_config().get('general', 'ca_implementation', fallback='openssl')

CRL_PORT = 38080

# Enable DB debugging via environment variable DEBUG_DB
# This is only effective when INSECURE_DEBUG is also True
DEBUG_DB = environ_bool('DEBUG_DB', False)
