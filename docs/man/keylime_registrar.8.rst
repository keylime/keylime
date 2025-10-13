=================
keylime_registrar
=================

------------------------------------------------
Keylime registrar service for agent registration
------------------------------------------------

:Manual section: 8
:Author: Keylime Developers
:Date: September 2025

SYNOPSIS
========

**keylime_registrar**

(Most operations require root privileges, use with sudo)

DESCRIPTION
===========

The registrar is a long-running service used by agents. It maintains its own database where it stores data
of registered agents. The service does not accept command-line options; behavior is
configured via configuration files and environment variables, and is managed by keylime tenant.

CONFIGURATION
=============

Primary configuration is read from ``/etc/keylime/registrar.conf`` (or an override via env).
All options are under the ``[registrar]`` section.

Essential configuration options:

**ip**
   Bind address

**port**
   HTTP port

**tls_port**
   HTTPS port

**tls_dir**
   TLS material location (``generate`` for auto-generate CA, keys, certs under ``$KEYLIME_DIR/reg_ca``, ``default`` for shared verifier CA under ``$KEYLIME_DIR/cv_ca``)

**server_key**, **server_key_password**, **server_cert**, **trusted_client_ca**
   TLS files

**database_url**
   SQLAlchemy URL; value ``sqlite`` maps to ``$KEYLIME_DIR/reg_data.sqlite``

**database_pool_sz_ovfl**
   Pool size, overflow (non-sqlite)

**auto_migrate_db**
   Apply DB migrations on startup

**max_upload_size**
   Request body limit (bytes)

**tpm_identity**
   Allowed identity (``default``, ``ek_cert_or_iak_idevid``, ``ek_cert``, ``iak_idevid``)

**malformed_cert_action**
   ``warn`` (default), ``reject``, or ``ignore``

**durable_attestation_import** (optional)
   Python import path to enable Durable Attestation

ENVIRONMENT
===========

**KEYLIME_REGISTRAR_CONFIG**
   Path to registrar.conf (highest priority)

**KEYLIME_LOGGING_CONFIG**
   Path to logging.conf

**KEYLIME_DIR**
   Working directory (default: ``/var/lib/keylime``)

**KEYLIME_TEST**
   ``on/true/1`` enables testing mode (looser checks; WORK_DIR becomes CWD)

FILES
=====

``/etc/keylime/registrar.conf``
   Registrar configuration file

``/etc/keylime/logging.conf``
   Logging configuration

``$KEYLIME_DIR/reg_data.sqlite``
   Database file when ``database_url = sqlite``

``$KEYLIME_DIR/reg_ca``
   TLS certificates when ``tls_dir = generate``

``$KEYLIME_DIR/cv_ca``
   Shared verifier certificates when ``tls_dir = default``

RUNTIME
=======

Start from system install:

.. code-block:: bash

   sudo keylime_registrar

Start as a systemd service:

.. code-block:: bash

   systemctl enable --now keylime_registrar

Open firewall ports (adjust if you changed ports):

.. code-block:: bash

   firewall-cmd --add-port=8890/tcp --add-port=8891/tcp
   firewall-cmd --runtime-to-permanent

NOTES
=====

- HTTPS is required for routes unless explicitly allowed insecure by the service.
- With ``tls_dir = default``, start the verifier before the registrar so the shared CA/certs exist in ``$KEYLIME_DIR/cv_ca``.
- The service forks worker processes (default: CPU count).
- Registrar and verifier may run on the same host or on separate hosts.

SEE ALSO
========

**keylime_verifier**\(8), **keylime_tenant**\(1), **keylime_agent**\(8)

BUGS
====

Report bugs at https://github.com/keylime/keylime/issues
