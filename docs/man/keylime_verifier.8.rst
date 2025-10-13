================
keylime_verifier
================

----------------------------------------------
Keylime verifier service for agent attestation
----------------------------------------------

:Manual section: 8
:Author: Keylime Developers
:Date: September 2025

SYNOPSIS
========

**keylime_verifier**

(Most operations require root privileges, use with sudo)

DESCRIPTION
===========

The verifier is a long-running service that attests registered agents. It accesses
the registrar database to obtain agent data, and optionally performs measured boot evaluation and durable
attestation. The service does not accept command-line options; its behavior is configured via
configuration files and environment variables, and it is managed by keylime tenant.

CONFIGURATION
=============

Primary configuration is read from ``/etc/keylime/verifier.conf`` (or an override via env).
All options are under the ``[verifier]`` section.

Essentials:
- **uuid**: Unique identifier for this verifier instance
- **ip**, **port**: Bind address and HTTP port
- **registrar_ip**, **registrar_port**: Registrar endpoint
- **enable_agent_mtls**: Enable mTLS with agents and tenant
- **tls_dir**: TLS material location

  - ``generate``: auto-generate CA, client and server keys/certs under ``$KEYLIME_DIR/cv_ca``
  - ``default``: use existing materials under ``$KEYLIME_DIR/cv_ca``

- **server_key**, **server_key_password**, **server_cert**: Server TLS files
- **client_key**, **client_key_password**, **client_cert**: Client TLS files
- **trusted_client_ca**, **trusted_server_ca**: CA lists
- **database_url**: SQLAlchemy URL; value ``sqlite`` maps to ``$KEYLIME_DIR/cv_data.sqlite``
- **database_pool_sz_ovfl**: Pool size, overflow (non-sqlite)
- **auto_migrate_db**: Apply DB migrations on startup
- **num_workers**: Number of worker processes (``0`` = CPU count)
- **exponential_backoff**, **retry_interval**, **max_retries**: Retry behavior for agent comm
- **quote_interval**: Time between integrity checks (seconds)
- **max_upload_size**: Upload size limit (bytes)
- **request_timeout**: Agent request timeout (seconds)
- **measured_boot_policy_name**, **measured_boot_imports**, **measured_boot_evaluate**: measured boot policy settings
- **severity_labels**, **severity_policy**: revocation severity config
- **ignore_tomtou_errors**: handle ToMToU IMA entries (bool)
- **durable_attestation_import** and related **persistent_store_url**, **transparency_log_url**,
  **time_stamp_authority_url**, **time_stamp_authority_certs_path**, **persistent_store_format**,
  **persistent_store_encoding**, **transparency_log_sign_algo**, **signed_attributes**: durable attestation
- **require_allow_list_signatures**: require signed allowlists (bool)

ENVIRONMENT
===========

- **KEYLIME_VERIFIER_CONFIG**: Path to verifier.conf (highest priority)
- **KEYLIME_LOGGING_CONFIG**: Path to logging.conf
- **KEYLIME_DIR**: Working directory (default: ``/var/lib/keylime``)
- **KEYLIME_TEST**: ``on/true/1`` enables testing mode (looser checks; WORK_DIR becomes CWD)

FILES
=====

- ``/etc/keylime/verifier.conf``
- ``/etc/keylime/logging.conf``
- ``$KEYLIME_DIR/cv_data.sqlite`` (when ``database_url = sqlite``)
- ``$KEYLIME_DIR/cv_ca`` (when ``tls_dir = default`` or ``generate``)
- systemd unit: ``keylime_verifier.service``

RUNTIME
=======

Start from system install:

.. code-block:: bash

   sudo keylime_verifier

Start as a systemd service:

.. code-block:: bash

    systemctl enable --now keylime_verifier

Open firewall ports (adjust if you changed ports):

.. code-block:: bash

    firewall-cmd --add-port 8881/tcp
    firewall-cmd --runtime-to-permanent

NOTES
=====

- Verifier initializes measured boot components on startup.
- With ``tls_dir = generate``, the verifier creates CA/keys/certs in ``$KEYLIME_DIR/cv_ca`` used by other components.

SEE ALSO
========

**keylime_registrar**\(8), **keylime_tenant**\(1), **keylime_agent**\(8)

BUGS
====

Report bugs at https://github.com/keylime/keylime/issues
