import ast


def adjust(config, mapping):  # pylint: disable=unused-argument
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
        "components": {
            "verifier": {
                "client_cert": {"CV": "default"},
                "trusted_server_ca": {"CV": "default"},
                "database_url": {"": "sqlite"},
            },
            "registrar": {"tls_dir": {"CV": "default"}, "database_url": {"": "sqlite"}},
        }
    }

    # Dictionary defining values to convert to lists
    tolist = {
        "components": {
            "agent": [
                "trusted_client_ca",
                "revocation_actions",
            ],
            "verifier": [
                "enabled_revocation_notifications",
                "trusted_server_ca",
                "severity_labels",
                "severity_policy",
                "measured_boot_imports",
            ],
            "tenant": [
                "trusted_server_ca",
                "accept_tpm_hash_algs",
                "accept_tpm_encryption_algs",
                "accept_tpm_signing_algs",
            ],
            "registrar": ["trusted_client_ca"],
        }
    }

    for component in replace["components"]:
        options = replace["components"][component]
        # For each option
        for option in options.keys():
            values = options[option]
            # For each value to replace
            for to_replace in values.keys():
                # If the value in the configuration matches the one to replace
                if config[component] and config[component][option] == to_replace:
                    # Replace the value
                    config[component][option] = values[to_replace]
                    print(f'[{component}] In "{option}", replaced "{to_replace}" ' f'with "{values[to_replace]}"')

    for component in tolist["components"]:
        for option in tolist["components"][component]:
            # Get raw string value
            value = config[component][option]

            if value == "default":
                continue

            try:
                v = ast.literal_eval(value)
                # If the value in the config was already a list, continue
                if isinstance(v, list):
                    continue

                # If the value in the config was tuple
                if isinstance(v, tuple):
                    config[component][option] = f"{list(v)}"

            except Exception:
                print(
                    f"[{component}] In option '{option}', failed to parse "
                    f"'{value}' as python type, trying manual splitting"
                )

                # Eliminate surrounding spaces and brackets, if present
                v = value.strip("[ ]").split(",")

                # Eliminate surrounding quotes and blank spaces from each element
                v = map(lambda x: x.strip(' "'), v)

                # Remove empty strings
                v = list(filter(lambda x: (x != ""), v))

                config[component][option] = f"{v}"

            print(f"[{component}] For option '{option}', converted '{value}' to " f"'{config[component][option]}'")

    # Other special adjustments
    if config["verifier"]["tls_dir"] == "generate":
        for o in ["client_key", "client_cert", "trusted_server_ca", "server_key", "server_cert", "trusted_client_ca"]:
            if not config["verifier"][o] == "default":
                config["verifier"][o] = "default"
                print(f"[verifier] Replaced option '{o}' with 'default' as " f"'tls_dir' is set as 'generate'")

    if config["registrar"]["tls_dir"] == "generate":
        for o in ["server_key", "server_cert", "trusted_client_ca"]:
            if not config["registrar"][o] == "default":
                config["registrar"][o] = "default"
                print(f"[registrar] Replaced option '{o}' with 'default' as " f"'tls_dir' is set as 'generate'")

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
