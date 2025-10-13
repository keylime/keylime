=============
keylime_agent
=============

-----------------------------------------------
Keylime agent service for TPM-based attestation
-----------------------------------------------

:Manual section: 8
:Author: Keylime Developers
:Date: September 2025

SYNOPSIS
========

**keylime_agent**

(Most operations require root privileges, use with sudo)

DESCRIPTION
===========

The agent is a long-running service that runs on systems to be attested. It communicates with
the TPM to generate quotes, collects IMA and measured boot event logs, and provides secure
payload functionality. The service does not accept command-line options; behavior is configured
via TOML configuration files.

CONFIGURATION
=============

Primary configuration is read from ``/etc/keylime/agent.conf`` (or an override via env).
Configuration uses TOML format. All options are under the ``[agent]`` section.

Drop-in overrides: files in ``/etc/keylime/agent.conf.d/`` are applied in lexicographic order.

Essential configuration options:

**uuid**
   Agent identifier (``generate``, ``hash_ek``, ``environment``, ``dmidecode``, ``hostname``, or explicit UUID)

**ip**, **port**
   Bind address and port (default: 9002)

**contact_ip**, **contact_port**
   External contact address (optional)

**registrar_ip**, **registrar_port**
   Registrar endpoint

**enable_agent_mtls**
   Enable mTLS communication

**tls_dir**
   TLS material location (``generate`` for auto-generate under ``$KEYLIME_DIR/cv_ca``, ``default`` for ``$KEYLIME_DIR/secure``)

**server_key**, **server_key_password**, **server_cert**
   TLS files (self-signed cert)

**trusted_client_ca**
   Trusted client CA list

**enc_keyname**
   Payload encryption key file name

**dec_payload_file**
   Decrypted payload file name

**secure_size**
   tmpfs partition size for secure storage

**tpm_ownerpassword**
   TPM owner password (``generate`` for random)

**extract_payload_zip**
   Auto-extract zip payloads (bool)

**enable_revocation_notifications**
   Listen for revocation via ZeroMQ (bool)

**revocation_notification_ip**, **revocation_notification_port**
   ZeroMQ endpoint

**revocation_cert**
   Certificate to verify revocation messages

**revocation_actions**
   Python scripts to run on revocation

**payload_script**
   Script to run after payload extraction

**enable_insecure_payload**
   Allow payloads without mTLS (insecure)

**measure_payload_pcr**
   PCR to extend with payload (-1 to disable)

**exponential_backoff**, **retry_interval**, **max_retries**
   TPM communication retry

**tpm_hash_alg**, **tpm_encryption_alg**, **tpm_signing_alg**
   TPM algorithms

**ek_handle**
   EK handle (``generate`` or explicit handle like ``0x81000000``)

**enable_iak_idevid**
   Enable IAK/IDevID usage (bool)

**iak_idevid_template**, **iak_idevid_asymmetric_alg**, **iak_idevid_name_alg**
   IAK/IDevID config

**idevid_password**, **idevid_handle**, **iak_password**, **iak_handle**
   Persistent key handles

**iak_cert**, **idevid_cert**
   Certificate file names

**run_as**
   User:group to drop privileges to

**ima_ml_path**
   IMA measurement log path (default: ``/sys/kernel/security/ima/ascii_runtime_measurements``)

**measuredboot_ml_path**
   Measured boot log path (default: ``/sys/kernel/security/tpm0/binary_bios_measurements``)

ENVIRONMENT
===========

**KEYLIME_AGENT_CONFIG**
   Path to agent.conf (highest priority)

**KEYLIME_LOGGING_CONFIG**
   Path to logging.conf

**KEYLIME_DIR**
   Working directory (default: ``/var/lib/keylime``)

**KEYLIME_AGENT_UUID**
   UUID when ``uuid = environment``

**KEYLIME_AGENT_IAK_CERT**
   Override iak_cert path

**KEYLIME_AGENT_IDEVID_CERT**
   Override idevid_cert path

**KEYLIME_TEST**
   ``on/true/1`` enables testing mode

FILES
=====

``/etc/keylime/agent.conf``
   TOML format configuration file

``/etc/keylime/agent.conf.d/``
   Drop-in snippets; read in lexicographic order

``/etc/keylime/logging.conf``
   Logging configuration

``$KEYLIME_DIR/secure/``
   Secure tmpfs mount for keys/payloads

``$KEYLIME_DIR/cv_ca/``
   TLS certificates when ``tls_dir = generate``

``$KEYLIME_DIR/tpmdata.yml``
   TPM state persistence

RUNTIME
=======

Start from system install:

.. code-block:: bash

   sudo keylime_agent

Start as a systemd service:

.. code-block:: bash

   sudo systemctl enable --now keylime_agent

Open firewall port:

.. code-block:: bash

   sudo firewall-cmd --add-port=9002/tcp
   sudo firewall-cmd --runtime-to-permanent

PREREQUISITES
=============

- Root privileges (use sudo)
- TPM 2.0 available (verify with ``tpm2_pcrread``)
- IMA enabled in kernel
- Network connectivity to registrar

NOTES
=====

- Agent uses TOML configuration format (unlike other Keylime components).
- The Rust agent is the current implementation; Python agent is deprecated.
- Agent generates self-signed certificates for mTLS if not provided.

SEE ALSO
========

**keylime_verifier**\(8), **keylime_registrar**\(8), **keylime_tenant**\(1)

BUGS
====

Report bugs at https://github.com/keylime/rust-keylime/issues
