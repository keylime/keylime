========================
Push-Model Attestation
========================

.. warning::
    Push-model attestation is currently experimental. The feature is functional
    but the API and configuration options may change in future releases.

Introduction
------------

In the default pull model, the Keylime verifier continuously polls agents for
attestation data. This requires the verifier to reach the agent over the network.

The push model reverses this: the agent initiates connections to the verifier and
proactively sends attestation evidence. This is useful when the verifier cannot
directly reach the agent, for example behind firewalls, NAT, or in edge/IoT
deployments.

For a detailed description of how push-model attestation works, see
:doc:`../design/push_model`.

Prerequisites
-------------

* Keylime verifier and registrar installed and running
* The ``keylime-push-model-agent`` binary installed on the target machine
* A TPM 2.0 device (hardware or emulated for development)
* Network connectivity **from the agent to the verifier and registrar** (the
  reverse is not required)
* The verifier's CA certificate available on the agent machine

Configuring the Verifier for Push Mode
--------------------------------------

Set the verifier's attestation mode to ``push`` in ``/etc/keylime/verifier.conf``:

.. code-block:: ini

    [verifier]
    mode = push

Or use a configuration snippet in ``/etc/keylime/verifier.conf.d/``:

.. code-block:: ini

    # /etc/keylime/verifier.conf.d/001-push-mode.conf
    [verifier]
    mode = push

The verifier can also be configured via environment variable:

.. code-block:: bash

    export KEYLIME_VERIFIER_MODE=push

.. note::
    The ``mode`` setting affects all agents on this verifier. A verifier in push
    mode expects agents to submit attestation data; it does not poll agents. A
    single verifier cannot operate in both modes simultaneously.

Additional verifier settings relevant to push mode:

* ``quote_interval``: Used to calculate the agent timeout threshold
  (``quote_interval * 5``). Default: ``2`` seconds.
* ``challenge_lifetime``: How long a challenge nonce remains valid for evidence
  submission.
* ``verification_timeout``: Maximum time allowed for evidence verification.

After changing the configuration, restart the verifier:

.. code-block:: bash

    sudo systemctl restart keylime_verifier

Configuring the Push-Model Agent
---------------------------------

The push-model agent is a separate binary from the standard Keylime agent. It is
installed as ``keylime_push_model_agent`` (or ``keylime-push-model-agent``).

The agent is configured through ``/etc/keylime/agent.conf`` (TOML format), command-line
arguments, or environment variables.

Key Configuration Options
"""""""""""""""""""""""""

The following options are specific to or particularly important for push-model
operation:

.. list-table::
   :header-rows: 1
   :widths: 30 15 55

   * - Option
     - Default
     - Description
   * - ``verifier_url``
     - ``https://localhost:8881``
     - URL of the verifier. Must use HTTPS.
   * - ``verifier_tls_ca_cert``
     - ``cv_ca/cacert.crt``
     - Path to the CA certificate for verifying the verifier's TLS certificate.
       Relative paths are resolved from ``keylime_dir``.
   * - ``attestation_interval_seconds``
     - ``60``
     - Interval in seconds between attestation cycles.
   * - ``registrar_ip``
     - ``127.0.0.1``
     - IP address of the registrar.
   * - ``registrar_port``
     - ``8890``
     - Port of the registrar.
   * - ``registrar_tls_enabled``
     - ``false``
     - Enable TLS for registrar communication.
   * - ``registrar_tls_ca_cert``
     - ``cv_ca/cacert.crt``
     - CA certificate for registrar TLS verification.
   * - ``uuid``
     - (generated)
     - Agent UUID. Can be a specific UUID, ``generate`` (random), or
       ``hash_ek`` (derived from the EK).
   * - ``api_versions``
     - ``3.0``
     - API versions supported by the agent. Defaults to ``3.0`` for push model.
   * - ``tpm_hash_alg``
     - ``sha256``
     - TPM hash algorithm (``sha256``, ``sha384``, ``sha512``).
   * - ``tpm_signing_alg``
     - ``rsassa``
     - TPM signing algorithm (``rsassa``, ``ecdsa``).
   * - ``keylime_dir``
     - ``/var/lib/keylime``
     - Working directory for certificates and data files.

Example Minimal Configuration
""""""""""""""""""""""""""""""

.. code-block:: toml

    # /etc/keylime/agent.conf (push-model agent)
    [agent]
    uuid = "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
    verifier_url = "https://verifier.example.com:8881"
    verifier_tls_ca_cert = "/var/lib/keylime/cv_ca/cacert.crt"
    attestation_interval_seconds = 60
    registrar_ip = "registrar.example.com"
    registrar_port = 8890
    tpm_hash_alg = "sha256"
    tpm_signing_alg = "rsassa"

Command-Line Arguments
""""""""""""""""""""""

The push-model agent accepts the following command-line arguments, which override
configuration file values:

.. code-block:: text

    --verifier-url <URL>                    Verifier URL (required)
    --registrar-url <URL>                   Registrar URL (default: http://127.0.0.1:8888)
    --agent-identifier <ID>                 Agent UUID
    --attestation-interval-seconds <SECS>   Attestation interval (default: 60)
    --ca-certificate <PATH>                 CA certificate for TLS verification
    --api-version <VERSION>                 API version (default: v3.0)
    --timeout <MS>                          Request timeout in milliseconds (default: 5000)
    --insecure                              Accept invalid TLS certificates (testing only)
    --avoid-tpm                             Use mock TPM (testing only)

Exponential Backoff
"""""""""""""""""""

When the agent encounters errors (network failures, verifier unavailable), it uses
exponential backoff for retries:

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Option
     - Default
     - Description
   * - ``exponential_backoff_initial_delay``
     - ``10000``
     - Initial delay in milliseconds (10 seconds)
   * - ``exponential_backoff_max_retries``
     - ``5``
     - Maximum number of retry attempts
   * - ``exponential_backoff_max_delay``
     - ``300000``
     - Maximum delay in milliseconds (5 minutes)

Systemd Service Management
---------------------------

The push-model agent is managed as a systemd service:

.. code-block:: bash

    # Enable the service to start on boot
    sudo systemctl enable keylime_push_model_agent

    # Start the service
    sudo systemctl start keylime_push_model_agent

    # Check service status
    sudo systemctl status keylime_push_model_agent

    # View logs
    sudo journalctl -u keylime_push_model_agent -f

.. warning::
    The push-model agent service (``keylime_push_model_agent.service``) conflicts
    with the standard pull-model agent service (``keylime_agent.service``). Only one
    can run at a time on the same machine. Starting one will stop the other.

The service is configured to restart on failure with a 120-second delay between
restart attempts.

Enrolling an Agent for Push-Model Attestation
---------------------------------------------

Use the ``keylime_tenant`` tool with the ``--push-model`` flag to enroll an agent
for push-model attestation:

.. code-block:: bash

    # Add an agent in push mode
    sudo keylime_tenant -c add --push-model -u <agent-uuid>

    # Add with a runtime IMA policy
    sudo keylime_tenant -c add --push-model -u <agent-uuid> \
        --runtime-policy-name <policy-name>

    # Add with a measured boot policy
    sudo keylime_tenant -c add --push-model -u <agent-uuid> \
        --mb-policy-name <policy-name>

.. note::
    In push mode, the ``-t`` / ``--targethost`` option is not required because the
    verifier does not need to connect to the agent. The agent's IP and port are set
    to ``None`` in the verifier's database.

To check the status of a push-model agent:

.. code-block:: bash

    sudo keylime_tenant -c cvstatus -u <agent-uuid>

To remove an agent:

.. code-block:: bash

    sudo keylime_tenant -c delete -u <agent-uuid>

TLS Configuration for Push Model
---------------------------------

The push model uses TLS differently from the pull model:

**Agent-to-verifier connection:**

* The agent connects to the verifier over HTTPS
* The agent verifies the verifier's server certificate using the configured CA
  certificate (``verifier_tls_ca_cert``)
* The agent does **not** present a client certificate (no mTLS)
* Authentication is done via PoP bearer tokens (see :doc:`authentication`)

**Agent-to-registrar connection:**

* The agent connects to the registrar to register itself
* TLS can be enabled with ``registrar_tls_enabled = true``
* The registrar CA certificate is configured with ``registrar_tls_ca_cert``

**Firewall considerations:**

* No inbound ports need to be opened on the agent machine
* The agent needs outbound access to the verifier port (default: 8881)
* The agent needs outbound access to the registrar port (default: 8890)

To set up TLS, copy the verifier's CA certificate to the agent machine:

.. code-block:: bash

    # On the verifier machine, the CA cert is typically at:
    # /var/lib/keylime/cv_ca/cacert.crt

    # Copy to the agent machine:
    scp verifier:/var/lib/keylime/cv_ca/cacert.crt /var/lib/keylime/cv_ca/cacert.crt

Verifying the Deployment
-------------------------

After starting both the verifier (in push mode) and the push-model agent:

1. **Check agent registration** in the registrar:

   .. code-block:: bash

       sudo keylime_tenant -c regstatus -u <agent-uuid>

2. **Check attestation status** in the verifier:

   .. code-block:: bash

       sudo keylime_tenant -c cvstatus -u <agent-uuid>

3. **View verifier logs** for attestation activity:

   .. code-block:: bash

       sudo journalctl -u keylime_verifier -f

   Successful attestations will show evidence receipt and verification completion
   messages.

4. **View agent logs** for attestation cycles:

   .. code-block:: bash

       sudo journalctl -u keylime_push_model_agent -f

   The agent logs will show transitions through the state machine:
   registration, negotiation, and attestation phases.

Troubleshooting
----------------

Agent cannot connect to verifier
"""""""""""""""""""""""""""""""""

* Verify the ``verifier_url`` is correct and uses HTTPS
* Check that the verifier is running and listening on the configured port
* Verify network connectivity from the agent to the verifier
* Check that the CA certificate (``verifier_tls_ca_cert``) matches the verifier's
  server certificate

Agent shows timeout failures
"""""""""""""""""""""""""""""

The verifier marks an agent as failed if it does not receive an attestation within
``quote_interval * 5`` seconds.

* Verify the ``attestation_interval_seconds`` on the agent is less than the
  verifier's timeout threshold
* Check for network instability between agent and verifier
* Review agent logs for errors during attestation cycles

PoP authentication errors
""""""""""""""""""""""""""

* Ensure the agent is properly registered in the registrar (the AK must be known)
* Check that the TPM is accessible and functioning
* Verify the agent UUID matches between agent configuration and verifier enrollment

Agent state stuck in Negotiating
"""""""""""""""""""""""""""""""""

* The verifier may be rejecting capabilities. Check verifier logs for error details
* Ensure the TPM algorithms configured on the agent are accepted by the verifier
* Check that the ``api_versions`` setting includes ``3.0``

Service fails to start
""""""""""""""""""""""

* Check that the pull-model agent service is not running
  (``systemctl status keylime_agent``)
* Verify the configuration file syntax (TOML format)
* Check file permissions on TLS certificates and TPM device
