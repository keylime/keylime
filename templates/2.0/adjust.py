import ast
import configparser
import re
from configparser import RawConfigParser
from typing import Dict, List, Optional, Tuple

from keylime.common.version import str_to_version


def adjust(config: RawConfigParser, mapping: Dict) -> None:  # pylint: disable=unused-argument
    """
    Process the configuration intermediary representation adjusting some of the
    values following changes to the configuration files semantics.

    For example, deciding values for some of the options depending on the
    content of the values in other options.  This is specially useful when some
    of the options were removed from one configuration version to the next.

    This is executed after the original configuration file is parsed, but before
    the values are replaced in the templates
    """

    print("Adjusting configuration")

    # Dictionary defining values to replace
    replace = {
        "verifier": {
            "client_cert": {"CV": "default"},
            "trusted_server_ca": {"CV": "default"},
            "database_url": {"": "sqlite"},
        },
        "registrar": {"tls_dir": {"CV": "default"}, "database_url": {"": "sqlite"}},
    }

    # List of all agent boolean values that need to be changed to lower case
    # (for TOML output)
    booleans = [
        "enable_agent_mtls",
        "extract_payload_zip",
        "enable_revocation_notifications",
        "enable_insecure_payload",
        "exponential_backoff",
    ]

    # Dictionary defining values to convert to lists
    tolist = {
        "agent": [
            "trusted_client_ca",
            "revocation_actions",
        ],
        "verifier": [
            "trusted_server_ca",
            "severity_labels",
            "severity_policy",
            "measured_boot_imports",
        ],
        "revocations": [
            "enabled_revocation_notifications",
        ],
        "tenant": [
            "trusted_server_ca",
            "accept_tpm_hash_algs",
            "accept_tpm_encryption_algs",
            "accept_tpm_signing_algs",
        ],
        "registrar": ["trusted_client_ca"],
    }

    for section in config:
        try:
            config_version = str_to_version(config[section].get("version", "1.0"))

            if not config_version:
                raise Exception("Invalid version number found in old configuration")

        except (configparser.NoOptionError, configparser.NoSectionError):
            print(f"No version found in old configuration for {section}, using '1.0'")
            config_version = (1, 0)

        mapping_version = str_to_version(mapping["version"])

        if config_version != mapping_version:
            # Do not apply adjustments if the section version doesn't match
            # the mapping version
            continue

        if section in replace:
            for option in replace[section]:
                value = replace[section][option]
                # For each value to replace
                for to_replace in value:
                    # If the value in the configuration matches the one to replace
                    if section in config and option in config[section] and config[section][option] == to_replace:
                        # Replace the value
                        config[section][option] = value[to_replace]
                        print(f'[{section}] In "{option}", replaced "{to_replace}" ' f'with "{value[to_replace]}"')

        if section in tolist:
            for option in tolist[section]:
                if section in config and option in config[section]:
                    # Get raw string value
                    value = config[section][option].strip(' "')

                    if value == "default":
                        continue

                    try:
                        v = ast.literal_eval(value)
                        # If the value in the config was already a list, continue
                        if isinstance(v, list):
                            continue

                        # If the value in the config was tuple
                        if isinstance(v, tuple):
                            config[section][option] = str(list(v))

                    except Exception as e:
                        print(
                            f"[{section}] In option '{option}', failed to parse "
                            f"'{value}' as python type, trying manual splitting"
                        )

                        # Eliminate surrounding spaces and brackets, if present
                        v = value.strip("[ ]").split(",")

                        # Eliminate surrounding quotes and blank spaces from each element
                        v = map(lambda x: x.strip(' "'), v)

                        # Remove empty strings
                        v = list(filter(lambda x: (x != ""), v))

                        config[section][option] = str(v)

                    print(f"[{section}] For option '{option}', converted '{value}' to " f"'{config[section][option]}'")

        # Other special adjustments

        # Convert agent boolean values to lower case (for TOML output)
        if section == "agent":
            for option in booleans:
                # If the option is present in the configuration
                if config[section] and option in config[section]:
                    # Replace the value with lowecase form
                    config[section][option] = config[section][option].lower()
                    print(f'[agent] Converted option "{option}" to lower case')

        if section == "verifier":
            if config["verifier"]["tls_dir"] == "generate":
                for o in [
                    "client_key",
                    "client_cert",
                    "trusted_server_ca",
                    "server_key",
                    "server_cert",
                    "trusted_client_ca",
                ]:
                    if not config["verifier"][o] == "default":
                        config["verifier"][o] = "default"
                        print(f"[verifier] Replaced option '{o}' with 'default' as " f"'tls_dir' is set as 'generate'")

        if section == "registrar":
            if config["registrar"]["tls_dir"] == "generate":
                for o in ["server_key", "server_cert", "trusted_client_ca"]:
                    if not config["registrar"][o] == "default":
                        config["registrar"][o] = "default"
                        print(f"[registrar] Replaced option '{o}' with 'default' as " f"'tls_dir' is set as 'generate'")

        if section == "tenant":
            # If the tenant's 'trusted_server_ca' is set as 'default' and both the
            # verifier's and registrar's 'tls_dir' are set as 'generate', assume the
            # user is trying to run locally and set the tenant's 'trusted_server_ca' to
            # include both CA certificate's paths.
            #
            # Note: If 'generate' is set for the registrar's 'tls_dir', the 'registrar'
            # will generate a separate CA from the verifier, meaning the user has to
            # manually set the tenant's 'trusted_server_ca' to include both locations.
            #
            # To make the registrar to use the verifier CA, set the registrar's
            # 'tls_dir' as 'default' instead of 'generate'
            if config["tenant"]["tls_dir"] == "default":
                if config["tenant"]["trusted_server_ca"] == "default":
                    if config["registrar"]["tls_dir"] == "generate":
                        if config["verifier"]["tls_dir"] == "generate":
                            config["tenant"][
                                "trusted_server_ca"
                            ] = "['/var/lib/keylime/cv_ca/cacert.crt', '/var/lib/keylime/reg_ca/cacert.crt']"
                            print(
                                f"[tenant] For option 'trusted_server_ca', replaced 'default' with "
                                f"'{config['tenant']['trusted_server_ca']}'"
                            )
