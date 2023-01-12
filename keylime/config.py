import ast
import logging
import os
import os.path
from configparser import RawConfigParser
from typing import Any, Dict, List, Optional, cast

import yaml

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader  # type: ignore

from yaml.reader import ReaderError

from keylime.common.version import str_to_version


def convert(data: Any) -> Any:
    if isinstance(data, bytes):
        return data.decode()
    if isinstance(data, dict):
        return dict(iter(map(convert, data.items())))
    if isinstance(data, tuple):
        return tuple(map(convert, data))
    if isinstance(data, list):
        return list(map(convert, data))
    return data


def environ_bool(env_name: str, default: bool) -> bool:
    val = os.getenv(env_name, "default").lower()
    if val in ["on", "true", "1"]:
        return True
    if val in ["off", "false", "0"]:
        return False
    if val == "default":
        return default
    raise ValueError(
        f"Environment variable {env_name} set to invalid value " f"{val} (use either on/true/1 or off/false/0)"
    )


# enable printing of keys and other info for debug purposes
INSECURE_DEBUG = False

# allow the emuatlor to not have an ekcert even if check ekcert is true
DISABLE_EK_CERT_CHECK_EMULATOR = False

# whether to use tpmfs or not
MOUNT_SECURE = True

DEFAULT_WORK_DIR = "/var/lib/keylime"
WORK_DIR = os.getenv("KEYLIME_DIR", DEFAULT_WORK_DIR)

# default templates directory
TEMPLATES_DIR = "/usr/share/keylime/templates"

# allow testing mode
TEST_MODE = environ_bool("KEYLIME_TEST", False)
if TEST_MODE:
    print(
        "WARNING: running keylime in testing mode.\nKeylime will:\n"
        "- Not check the ekcert for the TPM emulator\n"
        "- Not create a secure mount\n"
        "- Change the KEYLIME_DIR to CWD"
    )
    DISABLE_EK_CERT_CHECK_EMULATOR = True
    MOUNT_SECURE = False
    # Different default WORK_DIR in TEST_MODE
    WORK_DIR = os.getenv("KEYLIME_DIR", os.getcwd())

# Possible paths for base configuration files
CONFIG_FILES = {
    "agent": ["/etc/keylime/agent.conf", "/usr/etc/keylime/agent.conf"],
    "verifier": ["/etc/keylime/verifier.conf", "/usr/etc/keylime/verifier.conf"],
    "tenant": ["/etc/keylime/tenant.conf", "/usr/etc/keylime/tenant.conf"],
    "registrar": ["/etc/keylime/registrar.conf", "/usr/etc/keylime/registrar.conf"],
    "ca": ["/etc/keylime/ca.conf", "/usr/etc/keylime/ca.conf"],
    "logging": ["/etc/keylime/logging.conf", "/usr/etc/keylime/logging.conf"],
}

# Paths to directories in which options can be overriden using configuration
# snippets
CONFIG_SNIPPETS_DIRS = {
    "agent": ["/usr/etc/keylime/agent.conf.d", "/etc/keylime/agent.conf.d"],
    "verifier": ["/usr/etc/keylime/verifier.conf.d", "/etc/keylime/verifier.conf.d"],
    "tenant": ["/usr/etc/keylime/tenant.conf.d", "/etc/keylime/tenant.conf.d"],
    "registrar": ["/usr/etc/keylime/registrar.conf.d", "/etc/keylime/registrar.conf.d"],
    "ca": ["/usr/etc/keylime/ca.conf.d", "/etc/keylime/ca.conf.d"],
    "logging": ["/usr/etc/keylime/logging.conf.d", "/etc/keylime/logging.conf.d"],
}

CONFIG_ENV = {
    "agent": "",
    "verifier": "",
    "tenant": "",
    "registrar": "",
    "ca": "",
    "logging": "",
}

# Add files from environment variables, if set
if "KEYLIME_AGENT_CONFIG" in os.environ:
    CONFIG_ENV["agent"] = os.environ["KEYLIME_AGENT_CONFIG"]
if "KEYLIME_VERIFIER_CONFIG" in os.environ:
    CONFIG_ENV["verifier"] = os.environ["KEYLIME_VERIFIER_CONFIG"]
if "KEYLIME_TENANT_CONFIG" in os.environ:
    CONFIG_ENV["tenant"] = os.environ["KEYLIME_TENANT_CONFIG"]
if "KEYLIME_REGISTRAR_CONFIG" in os.environ:
    CONFIG_ENV["registrar"] = os.environ["KEYLIME_REGISTRAR_CONFIG"]
if "KEYLIME_CA_CONFIG" in os.environ:
    CONFIG_ENV["ca"] = os.environ["KEYLIME_CA_CONFIG"]
if "KEYLIME_LOGGING_CONFIG" in os.environ:
    CONFIG_ENV["logging"] = os.environ["KEYLIME_LOGGING_CONFIG"]

# Single instance
_config: Optional[Dict[str, RawConfigParser]] = None


def get_config(component: str) -> RawConfigParser:
    """Find the configuration file to use for the given component and apply the
    overrides defined by configuration snippets.

    Configuration files are expected to be installed by the distribution on
    /usr/etc/keylime or /etc/keylime. If a configuration file is found in
    /etc/keylime, the configuration file in /usr/etc/keylime is ignored.

    If a configuration file path is set through a KEYLIME_*_CONFIG environment
    variable, all configuration from other files for that component are ignored,
    meaning that the configuration file set through a environment variable has
    top priority.

    The system administrator can define overrides for the values through
    configuration snippets in /etc/keylime/<component>.config.d, where
    <component> is one of: "agent", "verifier", "tenant", "registrar", "ca", or
    "logging".

    The configuration processing follows the steps described below:

    * If a configuration path is set through environment variable, use the
    configuration from this file and ignore configuration from other files.
    * Check if the configuration file for the component is present in
    /usr/etc/keylime (e.g. /usr/etc/keylime/agent.conf). If found, this file is
    used as the base configuration file for the component
    * Check if the configuration file for the component is present in
    /etc/keylime (e.g. /etc/keylime/agent.conf). If found, set this file as the
    base configuration file for the component, ignoring any previously set base
    configuration file.
    * Find and apply any override from files in /etc/keylime/<component.d> to
    the base configuration
    * Find and apply any local user override from files in
    ~/config/keylime/<component.d>
    """

    global _config

    if not _config:
        _config = {}

    if not component:
        # If no component was specified, return an empty configuration
        raise Exception("No component provided to get_config")

    if component not in _config:  # pylint: disable=too-many-nested-blocks
        # Use RawConfigParser, so we can also use it as the logging config
        _config[component] = RawConfigParser()

        if not CONFIG_ENV or not isinstance(CONFIG_ENV, dict):
            raise Exception("Invalid CONFIG_ENV")

        if not component in CONFIG_ENV:
            raise Exception(f"Invalid component '{component}'")

        # Check for configuration set through environment variable. In case it
        # is, use the values from the file set through environment variable and
        # ignore the content from the other files.
        if CONFIG_ENV[component]:
            if os.path.exists(CONFIG_ENV[component]):
                if os.path.isfile(CONFIG_ENV[component]):
                    config_files = _config[component].read(CONFIG_ENV[component])
                    print(f"Reading configuration from {config_files}")
                    return _config[component]

                print(
                    f"Configuration file {CONFIG_ENV[component]} for"
                    f"{component} set through environment variable is "
                    "not a file, falling back to installed configuration"
                )
            else:
                print(
                    f"Configuration file {CONFIG_ENV[component]} for "
                    f"{component} set through environment variable not found, "
                    f"falling back to installed configuration"
                )

        if not CONFIG_FILES or not isinstance(CONFIG_FILES, dict):
            raise Exception("Invalid CONFIG_FILES")

        if not component in CONFIG_FILES:
            raise Exception(f"Invalid component {component}")

        # TODO - use logger and be sure that all variables have a
        # propper default, and the sections are initialized
        if not any(os.path.exists(c) for c in CONFIG_FILES[component]):
            print(f"Config file not found in {CONFIG_FILES[component]}. " f"Please see {__file__} for more details.")
        else:
            for c in CONFIG_FILES[component]:
                # Search for configuration file in order of priority given by
                # CONFIG_FILES. The first base configuration file found is used,
                # the others are ignored

                # Validate that at least one config file is present
                config_file = _config[component].read(c)
                # TODO - use the logger
                if config_file:
                    print(f"Reading configuration from {config_file}")

                    if not CONFIG_SNIPPETS_DIRS or not isinstance(CONFIG_SNIPPETS_DIRS, dict):
                        raise Exception("Invalid CONFIG_FILES")

                    if not component in CONFIG_SNIPPETS_DIRS:
                        raise Exception(f"Invalid component {component}")

                    for d in (x for x in CONFIG_SNIPPETS_DIRS[component] if os.path.exists(x)):
                        snippets = sorted(filter(os.path.isfile, (os.path.join(d, f) for f in os.listdir(d) if f)))
                        applied_snippets = _config[component].read(snippets)
                        if applied_snippets:
                            # TODO - use the logger
                            print(f"Applied configuration snippets from {d}")
                    break

    return _config[component]


def _get_env(component: str, option: str, section: Optional[str]) -> Optional[str]:
    opt_section = f"_{section.upper()}" if section else ""
    env_name = f"KEYLIME_{component.upper()}{opt_section}_{option.upper()}"
    return os.environ.get(env_name, None)


def getlist(component: str, option: str, section: Optional[str] = None) -> List[Any]:
    env_value = _get_env(component, option, section)
    if not section:
        section = component

    if env_value is not None:
        read = env_value.strip('" ')
    else:
        read = get_config(component).get(section, option).strip('" ')

    if read:
        try:
            l = ast.literal_eval(read)
            if isinstance(l, list):
                return [i.strip() if isinstance(i, str) else i for i in l]
            raise Exception(
                f"Config option '{option}' in section '{section}' " f"'of component {component} should be a list"
            )
        except Exception as e:
            raise Exception(
                f"Failed to get list from config for component '{component}', section '{section}', option '{option}'"
            ) from e

    raise Exception(f"Could not find option '{option}' in section '{section}' of component '{component}'")


def get(component: str, option: str, section: Optional[str] = None, fallback: str = "") -> str:
    env_value = _get_env(component, option, section)
    if not section:
        section = component

    if env_value is not None:
        return env_value.strip('" ')

    return get_config(component).get(section, option, fallback=fallback).strip('" ')


def getint(component: str, option: str, section: Optional[str] = None, fallback: int = -1) -> int:
    env_value = _get_env(component, option, section)
    if not section:
        section = component

    if env_value is not None:
        return int(env_value)

    return get_config(component).getint(section, option, fallback=fallback)


def getboolean(component: str, option: str, section: Optional[str] = None, fallback: bool = False) -> bool:
    env_value = _get_env(component, option, section)
    if not section:
        section = component

    if env_value is not None:
        env_value_lower = env_value.lower().strip('" ')
        if env_value_lower not in RawConfigParser.BOOLEAN_STATES:
            return fallback
        return RawConfigParser.BOOLEAN_STATES[env_value_lower]

    return get_config(component).getboolean(section, option, fallback=fallback)


def getfloat(component: str, option: str, section: Optional[str] = None, fallback: float = -1.0) -> float:
    env_value = _get_env(component, option, section)
    if not section:
        section = component

    if env_value is not None:
        return float(env_value)

    return get_config(component).getfloat(section, option, fallback=fallback)


def has_option(component: str, option: str, section: Optional[str] = None) -> bool:
    env_value = _get_env(component, option, section)
    if not section:
        section = component

    if env_value is not None:
        return True

    return get_config(component).has_option(section, option)


CA_WORK_DIR = f"{WORK_DIR}/ca/"


def yaml_to_dict(
    arry: Any, add_newlines: bool = True, logger: Optional[logging.Logger] = None
) -> Optional[Dict[Any, Any]]:
    converted_arry: List[str] = convert(arry)
    sep = "\n" if add_newlines else ""
    try:
        return cast(Dict[Any, Any], yaml.load(sep.join(converted_arry), Loader=SafeLoader))
    except ReaderError as err:
        if logger is not None:
            logger.warning("Could not load yaml as dict: %s", str(err))
    return None


def check_version(component: str, logger: Optional[logging.Logger] = None) -> bool:
    """
    Check component current configuration file version and return a boolean
    indicating whether an upgrade is available
    """

    if not os.path.exists(TEMPLATES_DIR):
        # If there are no templates available
        if logger:
            logger.warning("The configuration upgrade templates path %s does not exist", TEMPLATES_DIR)
        return False

    if not os.path.isdir(TEMPLATES_DIR):
        if logger:
            logger.warning("The path %s is not a directory", TEMPLATES_DIR)
        return False

    dirs = os.listdir(TEMPLATES_DIR)

    if not dirs:
        if logger:
            logger.warning(
                "The path %s does not contain version directories for config upgrade templates", TEMPLATES_DIR
            )
        return False

    # Sort in reverse order to get first the latest version available
    versions = sorted((x for x in set(map(str_to_version, dirs)) if x is not None), reverse=True)

    if not versions:
        if logger:
            logger.warning("The path %s does not contain valid config version upgrade directories", TEMPLATES_DIR)
        return False

    config_version = get(component, "version", fallback="1.0")
    cur_version = str_to_version(config_version)

    if not cur_version:
        raise Exception(f"Invalid version in {component} configuration file")

    # The latest version available is the first element
    latest = versions[0]

    if cur_version < latest:
        if cur_version[0] < latest[0]:
            # In case an major update is available, print warning
            if logger:
                logger.warning(
                    "A major configuration upgrade is available (from %d.%d to %d.%d). Run 'keylime_upgrade_config' to upgrade the configuration",
                    cur_version[0],
                    cur_version[1],
                    latest[0],
                    latest[1],
                )
            return True
        if logger:
            logger.info(
                "A minor configuration upgrade is available (from %d.%d to %d.%d). Run 'keylime_upgrade_config' to upgrade the configuration",
                cur_version[0],
                cur_version[1],
                latest[0],
                latest[1],
            )
        return True

    return False


IMA_ML = "/sys/kernel/security/ima/ascii_runtime_measurements"

IMA_PCR = 10

# measured boot addons
# PCRs 0-7: BIOS & UEFI
# PCRs 8-9: bootloader (grub)
# PCR 14: MokList, MokListX, and MokSBState
MEASUREDBOOT_PCRS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15]
MEASUREDBOOT_ML = "/sys/kernel/security/tpm0/binary_bios_measurements"

LIBEFIVAR = "libefivar.so.1"  # formerly "/usr/lib/x86_64-linux-gnu/libefivar.so"

# this is where data will be bound to a quote, MUST BE RESETABLE!
TPM_DATA_PCR = 16

# the size of the bootstrap key for AES-GCM 256bit
BOOTSTRAP_KEY_SIZE = 32

CRL_PORT = 38080

# Enable DB debugging via environment variable DEBUG_DB
# This is only effective when INSECURE_DEBUG is also True
DEBUG_DB = environ_bool("DEBUG_DB", False)
