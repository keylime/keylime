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

logging.basicConfig(level=logging.INFO)
base_logger = logging.getLogger("keylime.config")


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
    # Different default WORK_DIR in TEST_MODE
    WORK_DIR = os.getenv("KEYLIME_DIR", os.getcwd())

# Possible paths for base configuration files
CONFIG_FILES = {
    "verifier": ["/etc/keylime/verifier.conf", "/usr/etc/keylime/verifier.conf"],
    "tenant": ["/etc/keylime/tenant.conf", "/usr/etc/keylime/tenant.conf"],
    "registrar": ["/etc/keylime/registrar.conf", "/usr/etc/keylime/registrar.conf"],
    "ca": ["/etc/keylime/ca.conf", "/usr/etc/keylime/ca.conf"],
    "logging": ["/etc/keylime/logging.conf", "/usr/etc/keylime/logging.conf"],
}

# Paths to directories in which options can be overriden using configuration
# snippets
CONFIG_SNIPPETS_DIRS = {
    "verifier": ["/usr/etc/keylime/verifier.conf.d", "/etc/keylime/verifier.conf.d"],
    "tenant": ["/usr/etc/keylime/tenant.conf.d", "/etc/keylime/tenant.conf.d"],
    "registrar": ["/usr/etc/keylime/registrar.conf.d", "/etc/keylime/registrar.conf.d"],
    "ca": ["/usr/etc/keylime/ca.conf.d", "/etc/keylime/ca.conf.d"],
    "logging": ["/usr/etc/keylime/logging.conf.d", "/etc/keylime/logging.conf.d"],
}

CONFIG_ENV = {
    "verifier": "",
    "tenant": "",
    "registrar": "",
    "ca": "",
    "logging": "",
}

# Add files from environment variables, if set
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


def _check_file_permissions(component: str, file_path: str) -> bool:
    """Check if a config file has correct permissions and is readable.

    Args:
        component: The component name (e.g., 'verifier', 'agent')
        file_path: Path to the config file

    Returns:
        True if file is readable, False otherwise
    """
    if not os.path.exists(file_path):
        return False

    if not os.access(file_path, os.R_OK):
        import grp  # pylint: disable=import-outside-toplevel
        import pwd  # pylint: disable=import-outside-toplevel
        import stat  # pylint: disable=import-outside-toplevel

        try:
            file_stat = os.stat(file_path)
            owner = pwd.getpwuid(file_stat.st_uid).pw_name
            group = grp.getgrgid(file_stat.st_gid).gr_name
            mode = stat.filemode(file_stat.st_mode)
        except Exception:
            owner = group = mode = "unknown"

        base_logger.error(  # pylint: disable=logging-not-lazy
            "=" * 80
            + "\n"
            + "CRITICAL CONFIG ERROR: Config file %s exists but is not readable!\n"
            + "File permissions: %s (owner: %s, group: %s)\n"
            + "The keylime_%s service needs read access to this file.\n"
            + "Fix with: chown keylime:keylime %s && chmod 440 %s\n"
            + "=" * 80,
            file_path,
            mode,
            owner,
            group,
            component,
            file_path,
            file_path,
        )
        return False

    return True


def _validate_config_files(component: str, file_paths: List[str], files_read: List[str]) -> None:
    """Validate that config files were successfully parsed.

    Args:
        component: The component name (e.g., 'verifier', 'agent')
        file_paths: List of file paths that were attempted to be read
        files_read: List of files that ConfigParser successfully read
    """
    for file_path in file_paths:
        # Check file permissions first
        if not _check_file_permissions(component, file_path):
            continue

        if file_path not in files_read:
            base_logger.error(  # pylint: disable=logging-not-lazy
                "=" * 80
                + "\n"
                + "CRITICAL CONFIG ERROR: Config file %s exists but failed to parse!\n"
                + "This usually indicates duplicate keys within the same file.\n"
                + "Common issues:\n"
                + "  - Same option appears multiple times in the same [%s] section\n"
                + "  - Empty values (key = ) conflicting with defined values\n"
                + "  - Invalid INI file syntax\n"
                + "Please check the file for duplicate entries.\n"
                + "You can validate the file with: python3 -c \"import configparser; c = configparser.RawConfigParser(); print(c.read('%s'))\"\n"
                + "=" * 80,
                file_path,
                component,
                file_path,
            )


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
    <component> is one of: "verifier", "tenant", "registrar", "ca", or "logging".

    The configuration processing follows the steps described below:

    * If a configuration path is set through environment variable, use the
    configuration from this file and ignore configuration from other files.
    * Check if the configuration file for the component is present in
    /usr/etc/keylime (e.g. /usr/etc/keylime/verifier.conf). If found, this file is
    used as the base configuration file for the component
    * Check if the configuration file for the component is present in
    /etc/keylime (e.g. /etc/keylime/verifier.conf). If found, set this file as the
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

    conf_create_msg = (
        '\nPlease use "keylime_upgrade_config --defaults" to create a minimalistic set of configurations.\n'
    )

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
                    base_logger.info("Reading configuration from %s", config_files)
                    return _config[component]

                base_logger.info(
                    "Configuration file %s for %s set through environment variable is not a file, falling back to installed configuration",
                    CONFIG_ENV[component],
                    component,
                )
            else:
                base_logger.info(
                    "Configuration file %s for %s set through environment variable not found, falling back to installed configuration",
                    CONFIG_ENV[component],
                    component,
                )

        if not CONFIG_FILES or not isinstance(CONFIG_FILES, dict):
            raise Exception("Invalid CONFIG_FILES")

        if not component in CONFIG_FILES:
            raise Exception(f"Invalid component {component}")

        # TODO - be sure that all variables have a
        # propper default, and the sections are initialized
        if not any(os.path.exists(c) for c in CONFIG_FILES[component]):
            base_logger.warning(
                "Config file not found in %s. It is required by component %s. %s",
                CONFIG_FILES[component],
                __file__,
                conf_create_msg,
            )
        else:
            for c in CONFIG_FILES[component]:
                # Search for configuration file in order of priority given by
                # CONFIG_FILES. The first base configuration file found is used,
                # the others are ignored

                # Validate that at least one config file is present
                config_file = _config[component].read(c)

                # Validate the config file was parsed successfully
                _validate_config_files(component, [c], config_file)

                if config_file:
                    base_logger.info("Reading configuration from %s", config_file)

                    if not CONFIG_SNIPPETS_DIRS or not isinstance(CONFIG_SNIPPETS_DIRS, dict):
                        raise Exception("Invalid CONFIG_FILES")

                    if not component in CONFIG_SNIPPETS_DIRS:
                        raise Exception(f"Invalid component {component}")

                    for d in (x for x in CONFIG_SNIPPETS_DIRS[component] if os.path.exists(x)):
                        snippets = sorted(
                            [os.path.join(d, f) for f in os.listdir(d) if f and os.path.isfile(os.path.join(d, f))]
                        )
                        applied_snippets = _config[component].read(snippets)

                        # Validate all snippet files were parsed successfully
                        _validate_config_files(component, snippets, applied_snippets)

                        if applied_snippets:
                            base_logger.info("Applied configuration snippets from %s", d)

                    break

    return _config[component]


def _get_env(component: str, option: str, section: Optional[str]) -> Optional[str]:
    opt_section = f"_{section.upper()}" if section else ""
    env_name = f"KEYLIME_{component.upper()}{opt_section}_{option.upper()}"
    env_value = os.environ.get(env_name, None)
    if env_value is not None:
        log_msg = f'option "{option}" on section {section} for component {component}.conf was overriden by environment variable {env_name}'
        base_logger.info(log_msg.replace("on section None ", ""))

    return env_value


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

LIBEFIVAR = "libefivar.so.1"  # formerly "/usr/lib/x86_64-linux-gnu/libefivar.so"

# this is where data will be bound to a quote, MUST BE RESETABLE!
TPM_DATA_PCR = 16

# Enable DB debugging via environment variable DEBUG_DB
# This is only effective when INSECURE_DEBUG is also True
DEBUG_DB = environ_bool("DEBUG_DB", False)

# Default timeout and retry constants to avoid magic numbers throughout the codebase
DEFAULT_TIMEOUT = 60.0
DEFAULT_MAX_RETRIES = 5
