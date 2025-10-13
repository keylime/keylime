==============
keylime_tenant
==============

---------------------------------------------------------------------------
Keylime tenant management tool for agent provisioning and policy management
---------------------------------------------------------------------------

:Manual section: 1
:Author: Keylime Developers
:Date: July 2025

SYNOPSIS
========

**keylime_tenant** [*OPTIONS*] [*COMMAND*]

(Most operations require root privileges, use with sudo)

DESCRIPTION
===========

keylime_tenant is the primary command-line interface for managing Keylime agents and policies.
It allows users to provision agents with TPM-based attestation, manage runtime policies,
measured boot policies, and interact with Keylime registrar and verifier services.

The tenant can add, delete, update, and monitor agents, as well as manage various types of
policies including runtime policies (for IMA/EVM attestation) and measured boot policies
(for boot-time attestation). It supports both push and pull models for agent communication.

You can run keylime_tenant on the same system as the Keylime registrar or verifier, or on a separate system.

COMMANDS
========

**-c, --command** *COMMAND*
   Specify the command to execute. Valid commands are:

   - **add**: Add a new agent to the system (default)
   - **delete**: Remove an agent from the system
   - **update**: Update an existing agent's configuration
   - **regstatus**: Show agent status from registrar
   - **cvstatus**: Show agent status from cloud verifier
   - **status**: Show combined agent status
   - **reglist**: List all agents in registrar
   - **cvlist**: List all agents in cloud verifier
   - **reactivate**: Reactivate a failed agent
   - **regdelete**: Delete agent from registrar only
   - **bulkinfo**: Get bulk information about agents
   - **addruntimepolicy**: Add a runtime policy (requires --runtime-policy or --allowlist)
   - **showruntimepolicy**: Display a runtime policy (requires --runtime-policy-name)
   - **deleteruntimepolicy**: Remove a runtime policy (requires --runtime-policy-name)
   - **updateruntimepolicy**: Update a runtime policy (requires --runtime-policy-name)
   - **listruntimepolicy**: List all runtime policies
   - **addmbpolicy**: Add a measured boot policy (requires --mb-policy-name)
   - **showmbpolicy**: Display a measured boot policy (requires --mb-policy-name)
   - **deletembpolicy**: Remove a measured boot policy (requires --mb-policy-name)
   - **updatembpolicy**: Update a measured boot policy (requires --mb-policy-name)
   - **listmbpolicy**: List all measured boot policies

OPTIONS
=======

**-h, --help**
   Show help message and exit

**--push-model**
   Enable push model (avoid requests to keylime-agent)

**-t, --targethost** *AGENT_IP*
   The IP address of the host to provision

**-tp, --targetport** *AGENT_PORT*
   The port of the host to provision

**-r, --registrarhost** *REGISTRAR_IP*
   The IP address of the registrar where to retrieve the agents data from

**-rp, --registrarport** *REGISTRAR_PORT*
   The port of the registrar

**--cv_targethost** *CV_AGENT_IP*
   The IP address of the host to provision that the verifier will use (optional).
   Use only if different than argument to option -t/--targethost

**-v, --cv** *VERIFIER_IP*
   The IP address of the cloud verifier

**-vp, --cvport** *VERIFIER_PORT*
   The port of the cloud verifier

**-vi, --cvid** *VERIFIER_ID*
   The unique identifier of a cloud verifier

**-nvc, --no-verifier-check**
   Disable the check to confirm if the agent is being processed by the specified verifier.
   Use only with -c/--command delete or reactivate

**-u, --uuid** *AGENT_UUID*
   UUID for the agent to provision

**-f, --file** *FILE*
   Deliver the specified plaintext file to the provisioned agent

**--cert** *CA_DIR*
   Create and deliver a certificate using a CA created by ca-util.
   Pass in the CA directory or use "default" to use the standard directory

**-k, --key** *KEYFILE*
   An intermediate key file produced by user_data_encrypt

**-p, --payload** *PAYLOAD*
   Specify the encrypted payload to deliver with encrypted keys specified by -k

**--include** *INCL_DIR*
   Include additional files in provided directory in certificate zip file.
   Must be specified with --cert

**--runtime-policy** *RUNTIME_POLICY*
   Specify the file path of a runtime policy

**--runtime-policy-checksum** *RUNTIME_POLICY_CHECKSUM*
   Specify the SHA-256 checksum of a runtime policy

**--runtime-policy-sig-key** *RUNTIME_POLICY_SIG_KEY*
   Specify the public key file used to validate the runtime policy signature

**--runtime-policy-url** *RUNTIME_POLICY_URL*
   Specify the URL of a remote runtime policy

**--runtime-policy-name** *RUNTIME_POLICY_NAME*
   The name of the runtime policy to operate with

**--mb-policy** *MB_POLICY*
   The measured boot policy to operate with

**--mb-policy-name** *MB_POLICY_NAME*
   The name of the measured boot policy to operate with

**--tpm_policy** *TPM_POLICY*
   Specify a TPM policy in JSON format.
   Example: {"15":"0000000000000000000000000000000000000000"}

**--verify**
   Block on cryptographically checked key derivation confirmation from the agent
   once it has been provisioned

**--supported-version** *SUPPORTED_VERSION*
   API version that is supported by the agent. Detected automatically by default

DEPRECATED OPTIONS
==================

The following options are deprecated and may be removed in future versions:

**--allowlist** *ALLOWLIST*
   **DEPRECATED**: Migrate to runtime policies for continued functionality.
   Specify the file path of an allowlist

**--allowlist-url** *ALLOWLIST_URL*
   **DEPRECATED**: Migrate to runtime policies for continued functionality.
   Specify the URL of a remote allowlist

**--allowlist-name** *ALLOWLIST_NAME*
   **DEPRECATED**: Migrate to runtime policies for continued functionality.
   The name of allowlist to operate with

**--exclude** *IMA_EXCLUDE*
   **DEPRECATED**: Migrate to runtime policies for continued functionality.
   Specify the location of an IMA exclude list

**--mb_refstate** *MB_POLICY*
   **DEPRECATED**: Use --mb-policy instead.
   Specify the location of a measured boot reference state

**--signature-verification-key** *IMA_SIGN_VERIFICATION_KEYS*
   **DEPRECATED**: Provide verification keys as part of a runtime policy for continued functionality.
   Specify an IMA file signature verification key

EXAMPLES
========

**Add a new agent:**

.. code-block:: bash

   sudo keylime_tenant -c add -t 192.168.1.100 -u agent-001

**Add an agent with runtime policy:**

.. code-block:: bash

   sudo keylime_tenant -c add -t 192.168.1.100 -u agent-001 --runtime-policy /path/to/policy.json

**Check agent status:**

.. code-block:: bash

   sudo keylime_tenant -c status -u agent-001

**Delete an agent:**

.. code-block:: bash

   sudo keylime_tenant -c delete -u agent-001

**List all agents:**

.. code-block:: bash

   sudo keylime_tenant -c cvlist

**Add a runtime policy:**

.. code-block:: bash

   sudo keylime_tenant -c addruntimepolicy --runtime-policy-name my-policy --runtime-policy /path/to/policy.json

**Add a measured boot policy:**

.. code-block:: bash

   sudo keylime_tenant -c addmbpolicy --mb-policy-name my-mb-policy --mb-policy /path/to/mb-policy.json

**Provision agent with certificate delivery:**

.. code-block:: bash

   sudo keylime_tenant -c add -t 192.168.1.100 -u agent-001 --cert default

**Provision agent with custom verifier:**

.. code-block:: bash

   sudo keylime_tenant -c add -t 192.168.1.100 -u agent-001 -v 192.168.1.200 -vp 8881

FILES
=====

/etc/keylime/tenant.conf
   Default configuration file for keylime_tenant. Contains all tenant related settings.


PREREQUISITES
=============

- Keylime verifier service running (default: 127.0.0.1:8881)
- Keylime registrar service running (default: 127.0.0.1:8891)
- Root privileges (use sudo)
- Network connectivity to registrar and verifier services
- Valid TLS configuration in /etc/keylime/tenant.conf

SEE ALSO
========

**keylime_verifier**\(8), **keylime_registrar**\(8), **keylime_agent**\(8)

For more information about Keylime, visit: https://keylime.dev

BUGS
====

Report bugs to the Keylime project at: https://github.com/keylime/keylime/issues
