=============
Configuration
=============

Keylime is configured by files installed by default in ``/etc/keylime``.
The files are loaded following a hierarchical order in which the values set for
the options can be overridden by the next level.

For each component, a base configuration file (e.g.
``/etc/keylime/verifier.conf``) is loaded, setting the base values.
Then, the configuration snippets placed in the respective directory (e.g.
``/etc/keylime/verifier.conf.d``) are loaded, overriding the previously set
values.
Finally, options can be overridden via environment variables.

The following components can be configured:

.. list-table:: Components and configuration
    :header-rows: 1

    * - Component
      - Default base config file
      - Default snippets directory
    * - agent
      - ``/etc/keylime/agent.conf``
      - ``/etc/keylime/agent.conf.d``
    * - verifier
      - ``/etc/keylime/verifier.conf``
      - ``/etc/keylime/verifier.conf.d``
    * - registrar
      - ``/etc/keylime/registrar.conf``
      - ``/etc/keylime/registrar.conf.d``
    * - tenant
      - ``/etc/keylime/tenant.conf``
      - ``/etc/keylime/tenant.conf.d``
    * - ca
      - ``/etc/keylime/ca.conf``
      - ``/etc/keylime/ca.conf.d``
    * - logging
      - ``/etc/keylime/logging.conf``
      - ``/etc/keylime/logging.conf.d``

The next sections contain details of the configuration files

Configuration file processing order
-----------------------------------

The configurations are loaded in the following order:

1. Default (hardcoded) option values
2. Base configuration options, overriding previously set values

  * By default, located in ``/etc/keylime/<component>.conf`` for each component

3. Configuration snippets, overriding previously set values

 * By default, located in ``/etc/keylime/<component>.conf.d`` for each component
 * The configuration snippets are loaded in lexicographic order

4. Environment variables, overriding previously set values

 * The environment variables are in the form
   ``KEYLIME_{COMPONENT}_[SECTION_]{OPTION}``, for example
   ``KEYLIME_VERIFIER_SERVER_KEY``.

Configuration file format
-------------------------

The configuration files for all components are written in INI format, except for
the agent which is written in TOML format.

Each component contains a main section named after the component name (for
historical reasons).  For example, the main section of ``verifier.conf`` is
``[verifier]``.

Override configurations via configuration snippets
--------------------------------------------------

To override a configuration option using a configuration snippet, simply create
a file in the component's configuration snippets directory (e.g.
``/etc/keylime/verifier.conf.d`` to override options from
``/etc/keylime/verifier.conf``).

Note that the configuration snippets are loaded and processed in
lexicographic order, keeping the last value set for each option.
It is recommended to use a numeric prefix for the files to control the order in
which they should be processed (e.g. ``001-custom.conf``).

The configuration snippets need the section to be explicitly provided, meaning
that the snippets are required to be valid INI (or TOML in the case of the
agent) files.

For example, the following snippet placed in
``/etc/keylime/verifier.conf.d/0001-ip.conf`` can override the default verifier ip
address:

.. code-block:: ini

    [verifier]
    ip = 172.30.1.10

Override configurations via environment variables
-------------------------------------------------

It is possible to override configuration options by setting the desired value
through environment variables.
The environment variables are defined as
``KEYLIME_{COMPONENT}_[SECTION_]{OPTION}``

The section can be omitted if the option to set is located in the main section
(the section named after the component). Otherwise the section is required.

For example, to set the ``webhook_url` option from the `[revocations]`` section in
the ``verifier.conf`` file, the environment variable to set is
``KEYLIME_VERIFIER_REVOCATIONS_WEBHOOK_URL``.

To set an option located in the main section, for example the ``server_key``
option from the ``[verifier]`` section in the ``verifier.conf``, the environment
variable to set is ``KEYLIME_VERIFIER_SERVER_KEY`` (note that the section can be
omitted).

Configuraton upgrades
---------------------

When updating keylime, it is also recommended to upgrade the configuration to
make sure that the used configuration is compatible with the keylime version.

The ``keylime_upgrade_config`` script is installed by default with the keylime
components, and is the script that performs the configuration upgrade following
the upgrade mappings and templates.

By default, the configuration templates are installed in
``/usr/share/keylime/templates``. For each configuration version a respective
directory is installed in the templates directory.

The ``keylime_upgrade_config`` will take the current configuration files as input
(by default from ``/etc/keylime/``). For each component, the version of the
configuration file is checked against the available upgrade template versions to
decide if an upgrade is necessary or not. In case an upgrade is not necessary,
meaning all the components configuration files are up-to-date, the script does
not modify the configuration files.

For each component that needs upgrade, the script will process all the
transformations needed by each configuration version. For example, suppose the
installed configuration file is in version ``1.0`` and there are upgrade templates
available for the versions ``2.0`` and ``3.0``. The upgrade script will process the
transformations defined from the version ``1.0`` to the version ``2.0`` and then
from the version ``2.0`` to the version ``3.0``.

For each configuration upgrade template version, there are the following files:

* ``mapping.json``: This file defines the transformations that should be
  performed, mapping the configuration option from the older version to the
  configuration options in the new version.  If the mapping has the ``update``
  type, then it describes operations to transform the previous version to the
  next (adding, removing, or replacing options)
* ``<component>.j2``: These are templates for the configuration files. It defines
  the output format for the configuration file for each component.
* ``adjust.py``: This is an optional script that defines special adjustments that
  cannot be specified through the ``mapping.json`` file. It is executed after the
  mapping transformations are applied.

The main goal of the upgrade script is to keep the configuration changes made by
the user and keep the configuration files up-to-date.  For new options, the
default values are used.

The configuration upgrade script ``keylime_upgrade_script``
-----------------------------------------------------------

Run ``keylime_upgrade_config --help`` for the description of the supported
options.

When executed by the ``root`` user, the default output directory for the
``keylime_upgrade_config`` script is the ``/etc/keylime`` directory. The existing
configuration files are kept intact as backup and renamed with the ``.bkp`` extension
appended to the file names.

In case the ``--output`` option is provided to the ``keylime_upgrade_config``
script, the configuration files are written even when they were alredy
up-to-date using the available templates.  It can be seen as a way to force the
creation of the configuration fiels, fitting the options read into the new
templates.

Passing the ``--debug`` option to the ``keylime_upgrade_config``, the logging level
is set to ``DEBUG``, making the script more verbose.

The templates directory to be processed can be passed via the ``--templates``
option. If provided, the script will try to find the configuration upgrade
templates in the provided path instead of the default location
(``/usr/share/keylime/templates``)

To output files only for a subset of the components, the ``--component`` can be
provided multiple times.

To override input files (by default the ``/etc/keylime/<component>.conf`` for each
component), the ``--input`` option can be passed multiple times. Unknown
components are ignored.

To stop the processing in a target version, set the target version with the
``--version`` option.

To ignore the input files and use the default value for all options, the
``--defaults`` option can be provided

Finally, to process a single mapping file, the mapping file path can be passed
via the ``--mapping`` option

Attestation Models: Pull vs Push
---------------------------------

Keylime supports two attestation models that determine how the verifier obtains
attestation evidence from agents:

Pull Model (Traditional)
~~~~~~~~~~~~~~~~~~~~~~~~~

In the pull model, the verifier actively polls agents at regular intervals to
retrieve attestation evidence. This is the default and traditional mode of
operation.

**Use Cases:**

* Traditional deployments where the verifier can directly connect to agents
* Environments with stable network connectivity
* When you need fine-grained control over attestation frequency

Push Model (Agent-Driven)
~~~~~~~~~~~~~~~~~~~~~~~~~~

In the push model, agents periodically push their attestation evidence to the
verifier. This mode is useful when the verifier cannot directly connect to
agents (e.g., agents behind firewalls or NAT).

**Use Cases:**

* Agents deployed behind firewalls or NAT
* Cloud or edge deployments where direct connectivity is limited
* When agents need to control their own attestation schedule

.. note::
    The push model options were introduced in configuration version 2.5 and
   requires the push attestation agent.

Configuration Options Reference
--------------------------------

This section provides comprehensive tables of all configuration options for each
Keylime component, including default values, environment variable overrides, and
applicability to pull/push attestation models.

Verifier Configuration (``/etc/keylime/verifier.conf``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Common Options (Both Models)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :header-rows: 1
    :widths: 25 12 15 48

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``version``
      - ``2.5``
      - 2.0
      - ``KEYLIME_VERIFIER_VERSION``
    * - ``uuid``
      - ``default``
      - 2.0
      - ``KEYLIME_VERIFIER_UUID``
    * - ``ip``
      - ``"127.0.0.1"``
      - 2.0
      - ``KEYLIME_VERIFIER_IP``
    * - ``port``
      - ``8881``
      - 2.0
      - ``KEYLIME_VERIFIER_PORT``
    * - ``registrar_ip``
      - ``127.0.0.1``
      - 2.0
      - ``KEYLIME_VERIFIER_REGISTRAR_IP``
    * - ``registrar_port``
      - ``8891``
      - 2.0
      - ``KEYLIME_VERIFIER_REGISTRAR_PORT``
    * - ``enable_agent_mtls``
      - ``True``
      - 2.0
      - ``KEYLIME_VERIFIER_ENABLE_AGENT_MTLS``
    * - ``tls_dir``
      - ``generate``
      - 2.0
      - ``KEYLIME_VERIFIER_TLS_DIR``
    * - ``server_key``
      - ``default``
      - 2.0
      - ``KEYLIME_VERIFIER_SERVER_KEY``
    * - ``server_key_password``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_SERVER_KEY_PASSWORD``
    * - ``server_cert``
      - ``default``
      - 2.0
      - ``KEYLIME_VERIFIER_SERVER_CERT``
    * - ``trusted_client_ca``
      - ``default``
      - 2.0
      - ``KEYLIME_VERIFIER_TRUSTED_CLIENT_CA``
    * - ``client_key``
      - ``default``
      - 2.0
      - ``KEYLIME_VERIFIER_CLIENT_KEY``
    * - ``client_key_password``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_CLIENT_KEY_PASSWORD``
    * - ``client_cert``
      - ``default``
      - 2.0
      - ``KEYLIME_VERIFIER_CLIENT_CERT``
    * - ``trusted_server_ca``
      - ``default``
      - 2.0
      - ``KEYLIME_VERIFIER_TRUSTED_SERVER_CA``
    * - ``database_url``
      - ``sqlite``
      - 2.0
      - ``KEYLIME_VERIFIER_DATABASE_URL``
    * - ``database_pool_sz_ovfl``
      - ``5,10``
      - 2.0
      - ``KEYLIME_VERIFIER_DATABASE_POOL_SZ_OVFL``
    * - ``auto_migrate_db``
      - ``True``
      - 2.0
      - ``KEYLIME_VERIFIER_AUTO_MIGRATE_DB``
    * - ``num_workers``
      - ``0``
      - 2.0
      - ``KEYLIME_VERIFIER_NUM_WORKERS``
    * - ``max_upload_size``
      - ``104857600``
      - 2.0
      - ``KEYLIME_VERIFIER_MAX_UPLOAD_SIZE``
    * - ``measured_boot_policy_name``
      - ``accept-all``
      - 2.0
      - ``KEYLIME_VERIFIER_MEASURED_BOOT_POLICY_NAME``
    * - ``measured_boot_imports``
      - ``[]``
      - 2.0
      - ``KEYLIME_VERIFIER_MEASURED_BOOT_IMPORTS``
    * - ``measured_boot_evaluate``
      - ``once``
      - 2.0
      - ``KEYLIME_VERIFIER_MEASURED_BOOT_EVALUATE``
    * - ``severity_labels``
      - ``["info", "notice", ...]``
      - 2.0
      - ``KEYLIME_VERIFIER_SEVERITY_LABELS``
    * - ``severity_policy``
      - ``[{"event_id": ".*", ...}]``
      - 2.0
      - ``KEYLIME_VERIFIER_SEVERITY_POLICY``
    * - ``ignore_tomtou_errors``
      - ``False``
      - 2.0
      - ``KEYLIME_VERIFIER_IGNORE_TOMTOU_ERRORS``
    * - ``durable_attestation_import``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_DURABLE_ATTESTATION_IMPORT``
    * - ``persistent_store_url``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_PERSISTENT_STORE_URL``
    * - ``transparency_log_url``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_TRANSPARENCY_LOG_URL``
    * - ``time_stamp_authority_url``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_TIME_STAMP_AUTHORITY_URL``
    * - ``time_stamp_authority_certs_path``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_TIME_STAMP_AUTHORITY_CERTS_PATH``
    * - ``persistent_store_format``
      - ``json``
      - 2.0
      - ``KEYLIME_VERIFIER_PERSISTENT_STORE_FORMAT``
    * - ``persistent_store_encoding``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_PERSISTENT_STORE_ENCODING``
    * - ``transparency_log_sign_algo``
      - ``sha256``
      - 2.0
      - ``KEYLIME_VERIFIER_TRANSPARENCY_LOG_SIGN_ALGO``
    * - ``signed_attributes``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_SIGNED_ATTRIBUTES``
    * - ``require_allow_list_signatures``
      - ``False``
      - 2.0
      - ``KEYLIME_VERIFIER_REQUIRE_ALLOW_LIST_SIGNATURES``

Pull Model Specific Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :header-rows: 1
    :widths: 25 12 15 48

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``quote_interval``
      - ``2``
      - 2.0
      - ``KEYLIME_VERIFIER_QUOTE_INTERVAL``
    * - ``retry_interval``
      - ``2``
      - 2.0
      - ``KEYLIME_VERIFIER_RETRY_INTERVAL``
    * - ``max_retries``
      - ``5``
      - 2.0
      - ``KEYLIME_VERIFIER_MAX_RETRIES``
    * - ``exponential_backoff``
      - ``True``
      - 2.0
      - ``KEYLIME_VERIFIER_EXPONENTIAL_BACKOFF``
    * - ``request_timeout``
      - ``60.0``
      - 2.0
      - ``KEYLIME_VERIFIER_REQUEST_TIMEOUT``

Push Model Specific Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :header-rows: 1
    :widths: 25 12 15 48

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``mode``
      - (empty)
      - 2.5
      - ``KEYLIME_VERIFIER_REVOCATIONS_MODE``
    * - ``challenge_lifetime``
      - (empty)
      - 2.5
      - ``KEYLIME_VERIFIER_REVOCATIONS_CHALLENGE_LIFETIME``
    * - ``verification_timeout``
      - (empty)
      - 2.5
      - ``KEYLIME_VERIFIER_REVOCATIONS_VERIFICATION_TIMEOUT``

Revocations Section
^^^^^^^^^^^^^^^^^^^

.. list-table::
    :header-rows: 1
    :widths: 30 12 15 43

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``enabled_revocation_notifications``
      - ``['agent']``
      - 2.0
      - ``KEYLIME_VERIFIER_REVOCATIONS_ENABLED_REVOCATION_NOTIFICATIONS``
    * - ``zmq_ip``
      - ``127.0.0.1``
      - 2.0
      - ``KEYLIME_VERIFIER_REVOCATIONS_ZMQ_IP``
    * - ``zmq_port``
      - ``8992``
      - 2.0
      - ``KEYLIME_VERIFIER_REVOCATIONS_ZMQ_PORT``
    * - ``webhook_url``
      - (empty)
      - 2.0
      - ``KEYLIME_VERIFIER_REVOCATIONS_WEBHOOK_URL``

Registrar Configuration (``/etc/keylime/registrar.conf``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
    :header-rows: 1
    :widths: 30 12 15 43

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``version``
      - ``2.5``
      - 2.0
      - ``KEYLIME_REGISTRAR_VERSION``
    * - ``ip``
      - ``"127.0.0.1"``
      - 2.0
      - ``KEYLIME_REGISTRAR_IP``
    * - ``port``
      - ``8890``
      - 2.0
      - ``KEYLIME_REGISTRAR_PORT``
    * - ``tls_port``
      - ``8891``
      - 2.0
      - ``KEYLIME_REGISTRAR_TLS_PORT``
    * - ``tls_dir``
      - ``default``
      - 2.0
      - ``KEYLIME_REGISTRAR_TLS_DIR``
    * - ``server_key``
      - ``default``
      - 2.0
      - ``KEYLIME_REGISTRAR_SERVER_KEY``
    * - ``server_key_password``
      - (empty)
      - 2.0
      - ``KEYLIME_REGISTRAR_SERVER_KEY_PASSWORD``
    * - ``server_cert``
      - ``default``
      - 2.0
      - ``KEYLIME_REGISTRAR_SERVER_CERT``
    * - ``trusted_client_ca``
      - ``default``
      - 2.0
      - ``KEYLIME_REGISTRAR_TRUSTED_CLIENT_CA``
    * - ``database_url``
      - ``sqlite``
      - 2.0
      - ``KEYLIME_REGISTRAR_DATABASE_URL``
    * - ``database_pool_sz_ovfl``
      - ``5,10``
      - 2.0
      - ``KEYLIME_REGISTRAR_DATABASE_POOL_SZ_OVFL``
    * - ``auto_migrate_db``
      - ``True``
      - 2.0
      - ``KEYLIME_REGISTRAR_AUTO_MIGRATE_DB``
    * - ``durable_attestation_import``
      - (empty)
      - 2.0
      - ``KEYLIME_REGISTRAR_DURABLE_ATTESTATION_IMPORT``
    * - ``persistent_store_url``
      - (empty)
      - 2.0
      - ``KEYLIME_REGISTRAR_PERSISTENT_STORE_URL``
    * - ``transparency_log_url``
      - (empty)
      - 2.0
      - ``KEYLIME_REGISTRAR_TRANSPARENCY_LOG_URL``
    * - ``time_stamp_authority_url``
      - (empty)
      - 2.0
      - ``KEYLIME_REGISTRAR_TIME_STAMP_AUTHORITY_URL``
    * - ``time_stamp_authority_certs_path``
      - (empty)
      - 2.0
      - ``KEYLIME_REGISTRAR_TIME_STAMP_AUTHORITY_CERTS_PATH``
    * - ``persistent_store_format``
      - ``json``
      - 2.0
      - ``KEYLIME_REGISTRAR_PERSISTENT_STORE_FORMAT``
    * - ``persistent_store_encoding``
      - (empty)
      - 2.0
      - ``KEYLIME_REGISTRAR_PERSISTENT_STORE_ENCODING``
    * - ``transparency_log_sign_algo``
      - ``sha256``
      - 2.0
      - ``KEYLIME_REGISTRAR_TRANSPARENCY_LOG_SIGN_ALGO``
    * - ``signed_attributes``
      - ``ek_tpm,aik_tpm,ekcert``
      - 2.0
      - ``KEYLIME_REGISTRAR_SIGNED_ATTRIBUTES``
    * - ``tpm_identity``
      - ``default``
      - 2.1
      - ``KEYLIME_REGISTRAR_TPM_IDENTITY``
    * - ``malformed_cert_action``
      - ``warn``
      - 2.4
      - ``KEYLIME_REGISTRAR_MALFORMED_CERT_ACTION``

Tenant Configuration (``/etc/keylime/tenant.conf``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
    :header-rows: 1
    :widths: 30 12 15 43

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``version``
      - ``2.5``
      - 2.0
      - ``KEYLIME_TENANT_VERSION``
    * - ``verifier_ip``
      - ``127.0.0.1``
      - 2.0
      - ``KEYLIME_TENANT_VERIFIER_IP``
    * - ``verifier_port``
      - ``8881``
      - 2.0
      - ``KEYLIME_TENANT_VERIFIER_PORT``
    * - ``registrar_ip``
      - ``127.0.0.1``
      - 2.0
      - ``KEYLIME_TENANT_REGISTRAR_IP``
    * - ``registrar_port``
      - ``8891``
      - 2.0
      - ``KEYLIME_TENANT_REGISTRAR_PORT``
    * - ``tls_dir``
      - ``default``
      - 2.0
      - ``KEYLIME_TENANT_TLS_DIR``
    * - ``enable_agent_mtls``
      - ``True``
      - 2.0
      - ``KEYLIME_TENANT_ENABLE_AGENT_MTLS``
    * - ``client_key``
      - ``default``
      - 2.0
      - ``KEYLIME_TENANT_CLIENT_KEY``
    * - ``client_key_password``
      - (empty)
      - 2.0
      - ``KEYLIME_TENANT_CLIENT_KEY_PASSWORD``
    * - ``client_cert``
      - ``default``
      - 2.0
      - ``KEYLIME_TENANT_CLIENT_CERT``
    * - ``trusted_server_ca``
      - ``default``
      - 2.0
      - ``KEYLIME_TENANT_TRUSTED_SERVER_CA``
    * - ``tpm_cert_store``
      - ``/var/lib/keylime/tpm_cert_store``
      - 2.0
      - ``KEYLIME_TENANT_TPM_CERT_STORE``
    * - ``max_payload_size``
      - ``1048576``
      - 2.0
      - ``KEYLIME_TENANT_MAX_PAYLOAD_SIZE``
    * - ``accept_tpm_hash_algs``
      - ``['sha512', 'sha384', 'sha256']``
      - 2.0
      - ``KEYLIME_TENANT_ACCEPT_TPM_HASH_ALGS``
    * - ``accept_tpm_encryption_algs``
      - ``['ecc', 'rsa']``
      - 2.0
      - ``KEYLIME_TENANT_ACCEPT_TPM_ENCRYPTION_ALGS``
    * - ``accept_tpm_signing_algs``
      - ``['ecschnorr', 'rsassa']``
      - 2.0
      - ``KEYLIME_TENANT_ACCEPT_TPM_SIGNING_ALGS``
    * - ``exponential_backoff``
      - ``True``
      - 2.0
      - ``KEYLIME_TENANT_EXPONENTIAL_BACKOFF``
    * - ``retry_interval``
      - ``2``
      - 2.0
      - ``KEYLIME_TENANT_RETRY_INTERVAL``
    * - ``max_retries``
      - ``5``
      - 2.0
      - ``KEYLIME_TENANT_MAX_RETRIES``
    * - ``request_timeout``
      - ``60``
      - 2.0
      - ``KEYLIME_TENANT_REQUEST_TIMEOUT``
    * - ``require_ek_cert``
      - ``True``
      - 2.0
      - ``KEYLIME_TENANT_REQUIRE_EK_CERT``
    * - ``ek_check_script``
      - (empty)
      - 2.0
      - ``KEYLIME_TENANT_EK_CHECK_SCRIPT``
    * - ``mb_refstate``
      - (empty)
      - 2.0
      - ``KEYLIME_TENANT_MB_REFSTATE``

CA Configuration (``/etc/keylime/ca.conf``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
    :header-rows: 1
    :widths: 30 15 15 40

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``version``
      - ``2.5``
      - 2.0
      - ``KEYLIME_CA_VERSION``
    * - ``password``
      - ``default``
      - 2.0
      - ``KEYLIME_CA_PASSWORD``
    * - ``cert_country``
      - ``US``
      - 2.0
      - ``KEYLIME_CA_CERT_COUNTRY``
    * - ``cert_ca_name``
      - ``Keylime Certificate Authority``
      - 2.0
      - ``KEYLIME_CA_CERT_CA_NAME``
    * - ``cert_state``
      - ``MA``
      - 2.0
      - ``KEYLIME_CA_CERT_STATE``
    * - ``cert_locality``
      - ``Lexington``
      - 2.0
      - ``KEYLIME_CA_CERT_LOCALITY``
    * - ``cert_organization``
      - ``MITLL``
      - 2.0
      - ``KEYLIME_CA_CERT_ORGANIZATION``
    * - ``cert_org_unit``
      - ``53``
      - 2.0
      - ``KEYLIME_CA_CERT_ORG_UNIT``
    * - ``cert_ca_lifetime``
      - ``3650``
      - 2.0
      - ``KEYLIME_CA_CERT_CA_LIFETIME``
    * - ``cert_lifetime``
      - ``365``
      - 2.0
      - ``KEYLIME_CA_CERT_LIFETIME``
    * - ``cert_bits``
      - ``2048``
      - 2.0
      - ``KEYLIME_CA_CERT_BITS``
    * - ``cert_crl_dist``
      - ``http://localhost:38080/crl``
      - 2.0
      - ``KEYLIME_CA_CERT_CRL_DIST``

Agent Configuration (``/etc/keylime/agent.conf``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::
    The Python agent is deprecated and will be removed in version 7.0.0!
    Please migrate to the Rust-based agent from https://github.com/keylime/rust-keylime/

Common Options (Both Models)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :header-rows: 1
    :widths: 28 12 12 48

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``version``
      - ``"2.5"``
      - 2.0
      - ``KEYLIME_AGENT_VERSION``
    * - ``api_versions``
      - ``"default"``
      - 2.4
      - ``KEYLIME_AGENT_API_VERSIONS``
    * - ``uuid``
      - ``"d432fbb3-d2f1-4a97-9ef7-75bd81c00000"``
      - 2.0
      - ``KEYLIME_AGENT_UUID``
    * - ``ip``
      - ``"127.0.0.1"``
      - 2.0
      - ``KEYLIME_AGENT_IP``
    * - ``port``
      - ``9002``
      - 2.0
      - ``KEYLIME_AGENT_PORT``
    * - ``contact_ip``
      - ``"127.0.0.1"``
      - 2.0
      - ``KEYLIME_AGENT_CONTACT_IP``
    * - ``contact_port``
      - ``9002``
      - 2.0
      - ``KEYLIME_AGENT_CONTACT_PORT``
    * - ``registrar_ip``
      - ``"127.0.0.1"``
      - 2.0
      - ``KEYLIME_AGENT_REGISTRAR_IP``
    * - ``registrar_port``
      - ``8890``
      - 2.0
      - ``KEYLIME_AGENT_REGISTRAR_PORT``
    * - ``enable_agent_mtls``
      - ``true``
      - 2.0
      - ``KEYLIME_AGENT_ENABLE_AGENT_MTLS``
    * - ``tls_dir``
      - ``"default"``
      - 2.0
      - ``KEYLIME_AGENT_TLS_DIR``
    * - ``server_key``
      - ``"default"``
      - 2.0
      - ``KEYLIME_AGENT_SERVER_KEY``
    * - ``server_key_password``
      - ``""``
      - 2.0
      - ``KEYLIME_AGENT_SERVER_KEY_PASSWORD``
    * - ``server_cert``
      - ``"default"``
      - 2.0
      - ``KEYLIME_AGENT_SERVER_CERT``
    * - ``trusted_client_ca``
      - ``"default"``
      - 2.0
      - ``KEYLIME_AGENT_TRUSTED_CLIENT_CA``
    * - ``enc_keyname``
      - ``"derived_tci_key"``
      - 2.0
      - ``KEYLIME_AGENT_ENC_KEYNAME``
    * - ``dec_payload_file``
      - ``"decrypted_payload"``
      - 2.0
      - ``KEYLIME_AGENT_DEC_PAYLOAD_FILE``
    * - ``secure_size``
      - ``"1m"``
      - 2.0
      - ``KEYLIME_AGENT_SECURE_SIZE``
    * - ``tpm_ownerpassword``
      - ``""``
      - 2.0
      - ``KEYLIME_AGENT_TPM_OWNERPASSWORD``
    * - ``extract_payload_zip``
      - ``true``
      - 2.0
      - ``KEYLIME_AGENT_EXTRACT_PAYLOAD_ZIP``
    * - ``enable_revocation_notifications``
      - ``true``
      - 2.0
      - ``KEYLIME_AGENT_ENABLE_REVOCATION_NOTIFICATIONS``
    * - ``revocation_notification_ip``
      - ``"127.0.0.1"``
      - 2.0
      - ``KEYLIME_AGENT_REVOCATION_NOTIFICATION_IP``
    * - ``revocation_notification_port``
      - ``8992``
      - 2.0
      - ``KEYLIME_AGENT_REVOCATION_NOTIFICATION_PORT``
    * - ``revocation_cert``
      - ``"default"``
      - 2.0
      - ``KEYLIME_AGENT_REVOCATION_CERT``
    * - ``revocation_actions``
      - ``"[]"``
      - 2.0
      - ``KEYLIME_AGENT_REVOCATION_ACTIONS``
    * - ``payload_script``
      - ``"autorun.sh"``
      - 2.0
      - ``KEYLIME_AGENT_PAYLOAD_SCRIPT``
    * - ``enable_insecure_payload``
      - ``false``
      - 2.0
      - ``KEYLIME_AGENT_ENABLE_INSECURE_PAYLOAD``
    * - ``measure_payload_pcr``
      - ``-1``
      - 2.0
      - ``KEYLIME_AGENT_MEASURE_PAYLOAD_PCR``
    * - ``exponential_backoff``
      - ``true``
      - 2.0
      - ``KEYLIME_AGENT_EXPONENTIAL_BACKOFF``
    * - ``retry_interval``
      - ``2``
      - 2.0
      - ``KEYLIME_AGENT_RETRY_INTERVAL``
    * - ``max_retries``
      - ``4``
      - 2.0
      - ``KEYLIME_AGENT_MAX_RETRIES``
    * - ``tpm_hash_alg``
      - ``"sha256"``
      - 2.0
      - ``KEYLIME_AGENT_TPM_HASH_ALG``
    * - ``tpm_encryption_alg``
      - ``"rsa"``
      - 2.0
      - ``KEYLIME_AGENT_TPM_ENCRYPTION_ALG``
    * - ``tpm_signing_alg``
      - ``"rsassa"``
      - 2.0
      - ``KEYLIME_AGENT_TPM_SIGNING_ALG``
    * - ``ek_handle``
      - ``"generate"``
      - 2.0
      - ``KEYLIME_AGENT_EK_HANDLE``
    * - ``enable_iak_idevid``
      - ``false``
      - 2.1
      - ``KEYLIME_AGENT_ENABLE_IAK_IDEVID``
    * - ``iak_idevid_template``
      - ``"detect"``
      - 2.1
      - ``KEYLIME_AGENT_IAK_IDEVID_TEMPLATE``
    * - ``iak_idevid_asymmetric_alg``
      - ``"rsa"``
      - 2.1
      - ``KEYLIME_AGENT_IAK_IDEVID_ASYMMETRIC_ALG``
    * - ``iak_idevid_name_alg``
      - ``"sha256"``
      - 2.1
      - ``KEYLIME_AGENT_IAK_IDEVID_NAME_ALG``
    * - ``idevid_password``
      - ``""``
      - 2.3
      - ``KEYLIME_AGENT_IDEVID_PASSWORD``
    * - ``idevid_handle``
      - ``""``
      - 2.3
      - ``KEYLIME_AGENT_IDEVID_HANDLE``
    * - ``iak_password``
      - ``""``
      - 2.3
      - ``KEYLIME_AGENT_IAK_PASSWORD``
    * - ``iak_handle``
      - ``""``
      - 2.3
      - ``KEYLIME_AGENT_IAK_HANDLE``
    * - ``iak_cert``
      - ``"default"``
      - 2.1
      - ``KEYLIME_AGENT_IAK_CERT``
    * - ``idevid_cert``
      - ``"default"``
      - 2.1
      - ``KEYLIME_AGENT_IDEVID_CERT``
    * - ``run_as``
      - ``"keylime:tss"``
      - 2.0
      - ``KEYLIME_AGENT_RUN_AS``
    * - ``ima_ml_path``
      - ``"default"``
      - 2.2
      - ``KEYLIME_AGENT_IMA_ML_PATH``
    * - ``measuredboot_ml_path``
      - ``"default"``
      - 2.2
      - ``KEYLIME_AGENT_MEASUREDBOOT_ML_PATH``

Push Model Specific Options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. list-table::
    :header-rows: 1
    :widths: 35 12 12 41

    * - Option
      - Default
      - Version
      - Environment Variable
    * - ``agent_data_path``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_AGENT_DATA_PATH``
    * - ``verifier_url``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_VERIFIER_URL``
    * - ``certification_keys_server_identifier``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_CERTIFICATION_KEYS_SERVER_IDENTIFIER``
    * - ``disabled_signing_algorithms``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_DISABLED_SIGNING_ALGORITHMS``
    * - ``ima_ml_count_file``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_IMA_ML_COUNT_FILE``
    * - ``uefi_logs_evidence_version``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_UEFI_LOGS_EVIDENCE_VERSION``
    * - ``exponential_backoff_max_retries``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_EXPONENTIAL_BACKOFF_MAX_RETRIES``
    * - ``exponential_backoff_initial_delay``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_EXPONENTIAL_BACKOFF_INITIAL_DELAY``
    * - ``exponential_backoff_max_delay``
      - ``""``
      - 2.5
      - ``KEYLIME_AGENT_EXPONENTIAL_BACKOFF_MAX_DELAY``

Logging Configuration (``/etc/keylime/logging.conf``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The logging configuration follows Python's standard logging configuration format.
See the Python logging documentation for details on configuring handlers, formatters,
and loggers. The version option can be overridden with ``KEYLIME_LOGGING_VERSION``.

Configuration Version History
------------------------------

.. list-table::
    :header-rows: 1
    :widths: 15 70

    * - Version
      - Changes
    * - 2.0
      - Base configuration structure, pull model support
    * - 2.1
      - Added IAK/IDevID support, ``tpm_identity`` for registrar
    * - 2.2
      - Added ``ima_ml_path`` and ``measuredboot_ml_path`` configuration
    * - 2.3
      - Added persisted key handles for IAK/IDevID (``iak_handle``, ``idevid_handle``)
    * - 2.4
      - Added ``api_versions`` for agent, ``malformed_cert_action`` for registrar
    * - 2.5
      - **Push model support**: Added ``mode``, ``challenge_lifetime``, ``verification_timeout`` for verifier; ``verifier_url``, ``agent_data_path``, exponential backoff options for agent

For detailed information on all configuration options for each component, refer
to the configuration files in ``/etc/keylime/`` and their inline documentation.
