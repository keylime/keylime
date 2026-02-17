==========================
keylime_push_model_agent
==========================

------------------------------------------------------------
Keylime push-model agent for TPM-based remote attestation
------------------------------------------------------------

:Manual section: 8
:Author: Keylime Developers
:Date: February 2026

SYNOPSIS
========

**keylime_push_model_agent** [*OPTIONS*]

(Most operations require root privileges, use with sudo)

DESCRIPTION
===========

The push-model agent is a long-running service that runs on systems to be attested.
Unlike the standard Keylime agent which acts as a server and waits for the verifier
to poll it, the push-model agent initiates connections to the verifier and proactively
submits attestation evidence.

The agent registers with the registrar, authenticates with the verifier using Proof of
Possession (PoP), and performs periodic attestation cycles consisting of capabilities
negotiation and evidence submission.

This agent uses API version 3.0 and requires the verifier to be configured in push
mode (``mode = push``).

OPTIONS
=======

**--verifier-url** *URL*
   URL of the verifier (must use HTTPS). Default: ``https://localhost:8881``

**--registrar-url** *URL*
   URL of the registrar. Default: ``http://127.0.0.1:8888``

**--agent-identifier** *ID*
   Agent UUID. Overrides the ``uuid`` configuration option.

**--attestation-interval-seconds** *SECONDS*
   Interval between attestation cycles. Default: ``60``

**--ca-certificate** *PATH*
   CA certificate file for verifying the verifier's TLS certificate. Overrides
   ``verifier_tls_ca_cert``.

**--api-version** *VERSION*
   API version to use. Default: ``v3.0``

**--timeout** *MILLISECONDS*
   HTTP request timeout. Default: ``5000``

**--insecure**
   Accept invalid TLS certificates. For testing only.

**--avoid-tpm**
   Use a mock TPM instead of hardware TPM. For testing only.

**--json-file** *FILE*
   JSON file for payload data.

**--attestation-index** *INDEX*
   Attestation index value. Default: ``1``

**--session-index** *INDEX*
   Session index value. Default: ``1``

**--message-type** *TYPE*
   Message type (Attestation, EvidenceHandling, Session). Default: ``Attestation``

**--method** *METHOD*
   HTTP method. Default: ``POST``

CONFIGURATION
=============

Primary configuration is read from ``/etc/keylime/agent.conf`` (TOML format).
All options are under the ``[agent]`` section. Command-line arguments override
configuration file values.

Drop-in overrides: files in ``/etc/keylime/agent.conf.d/`` are applied in
lexicographic order.

Push-model specific options:

**verifier_url**
   URL of the verifier. Must use HTTPS. Default: ``https://localhost:8881``

**verifier_tls_ca_cert**
   Path to CA certificate for verifying the verifier's TLS certificate.
   Relative paths are resolved from ``keylime_dir``. Default: ``cv_ca/cacert.crt``

**attestation_interval_seconds**
   Interval in seconds between attestation cycles. Default: ``60``

**api_versions**
   API versions to use. Default: ``3.0``

**certification_keys_server_identifier**
   Server identifier for attestation key certification. Default: ``ak``

**uefi_logs_evidence_version**
   UEFI logs evidence format version. Default: ``2.1``

**exponential_backoff_initial_delay**
   Initial retry delay in milliseconds. Default: ``10000``

**exponential_backoff_max_retries**
   Maximum number of retry attempts. Default: ``5``

**exponential_backoff_max_delay**
   Maximum retry delay in milliseconds. Default: ``300000``

Shared options (same as standard agent):

**uuid**
   Agent identifier. Default: auto-generated UUID.

**registrar_ip**, **registrar_port**
   Registrar endpoint. Default: ``127.0.0.1:8890``

**registrar_tls_enabled**
   Enable TLS for registrar communication. Default: ``false``

**registrar_tls_ca_cert**
   CA certificate for registrar TLS verification. Default: ``cv_ca/cacert.crt``

**tpm_hash_alg**, **tpm_encryption_alg**, **tpm_signing_alg**
   TPM algorithms. Defaults: ``sha256``, ``rsa``, ``rsassa``

**keylime_dir**
   Working directory. Default: ``/var/lib/keylime``

**run_as**
   User:group to drop privileges to. Default: ``keylime:tss``

**enable_iak_idevid**
   Enable IAK/IDevID usage. Default: ``false``

ENVIRONMENT
===========

**KEYLIME_AGENT_CONFIG**
   Path to agent.conf (highest priority)

**KEYLIME_DIR**
   Working directory (default: ``/var/lib/keylime``)

**RUST_LOG**
   Log level configuration. Default in systemd service:
   ``keylime_push_model_agent=info,keylime=info``

All configuration options can be overridden via environment variables in the form
``KEYLIME_AGENT_<OPTION_NAME>`` (e.g. ``KEYLIME_AGENT_VERIFIER_URL``).

FILES
=====

``/etc/keylime/agent.conf``
   TOML format configuration file (shared with standard agent)

``/etc/keylime/agent.conf.d/``
   Drop-in configuration snippets

``/var/lib/keylime/cv_ca/cacert.crt``
   Default CA certificate for verifier TLS verification

``/var/lib/keylime/agent_data.json``
   Persisted agent TPM data

RUNTIME
=======

Start directly:

.. code-block:: bash

   sudo keylime_push_model_agent --verifier-url https://verifier.example.com:8881

Start as a systemd service:

.. code-block:: bash

   sudo systemctl enable --now keylime_push_model_agent

Check service status:

.. code-block:: bash

   sudo systemctl status keylime_push_model_agent
   sudo journalctl -u keylime_push_model_agent -f

PREREQUISITES
=============

- Root privileges (use sudo)
- TPM 2.0 available (verify with ``tpm2_pcrread``)
- Verifier configured with ``mode = push``
- Network connectivity from agent to verifier and registrar
- Verifier CA certificate available on agent machine

NOTES
=====

- This service conflicts with ``keylime_agent.service``. Only one agent type can
  run on a machine at a time.
- The push-model agent does not expose any listening ports.
- Push-model attestation is currently experimental.
- Authentication uses PoP bearer tokens, not mTLS client certificates.

SEE ALSO
========

**keylime_agent**\(8), **keylime_verifier**\(8), **keylime_registrar**\(8), **keylime_tenant**\(1)

BUGS
====

Report bugs at https://github.com/keylime/rust-keylime/issues
