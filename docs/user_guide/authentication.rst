Authentication
--------------
Most API interactions are secured using mTLS connections. By default there are two CAs involved,
but the components can be configured to accommodate more complex setups.

(The revocation process also uses a CA, but this is different to those CAs)

In push mode, the PoP (Proof of Possession) authentication is mandatory for
requests by agents for attestation operations.

**Security Note**: Never distribute client certificates signed by the verifier's trusted
CA to agents. In push-attestation, agents should only authenticate using PoP
tokens. In pull-model, agent should use its self-signed server certificate. If
an agent had a valid client certificate AND didn't send an Authorization header,
they would be identified as an admin by the verifier.

Server Components CA
~~~~~~~~~~~~~~~~~~~~
This CA is created by verifier on startup.
It contains the server certificates and keys used by the verifier and registrar for their respective HTTPS interfaces.
Then it also contains the client certificates and keys that are used by the tenant to connect to the registrar, verifier
and agent. Also the verifier uses that certificate to authenticate itself against the agent.

Agent Keylime CA
~~~~~~~~~~~~~~~~
The agent runs an HTTPS server and provides its certificate to the registrar (:code:`mtls_cert`).

The server component CA certificate is also required on the agent to authenticate connections
from the tenant and verifier. By default :code:`/var/lib/keylime/cv_ca/cacert.crt` is used.

Authorization Framework
-----------------------

Starting from version 7.14.0 (API version 2.5), Keylime implements a pluggable
authorization framework to control access to API operations. The framework
separates authentication (proving identity) from authorization (permission to
perform actions).

Overview
~~~~~~~~

Keylime's authorization framework is pluggable, allowing different authorization
providers to implement various access control policies. Each provider can define
its own rules for determining which identities can perform which operations.

Authorization Providers
~~~~~~~~~~~~~~~~~~~~~~~

The authorization provider is configured separately for each component:

**Verifier Configuration**

.. code-block:: ini

   [verifier]
   authorization_provider = simple

**Registrar Configuration**

.. code-block:: ini

   [registrar]
   authorization_provider = simple

**Available Providers**

* ``simple`` (default): Role-based access control with strict separation between
  agent and admin authentication methods

Future providers may include LDAP, OPA (Open Policy Agent), or custom implementations
for enterprise deployments requiring fine-grained RBAC.

SimpleAuthProvider
~~~~~~~~~~~~~~~~~~

The ``simple`` provider is the default authorization provider. It classifies
operations into four categories:

* **Public operations**: No authentication required

  * Version information (``GET /versions``)
  * Server information (``GET /``)
  * Identity verification (``GET /verify/identity``)
  * Evidence verification (``POST /verify/evidence``)
  * Session creation for push attestation (``POST /sessions``)
  * Session update/extend (``PATCH /sessions/:session_id``)

* **Agent-only operations**: Requires PoP bearer token authentication

  * Agents can only access their own resources (identity must match resource)
  * Submit attestations (``POST /agents/:agent_id/attestations``)

* **Agent-or-admin operations**: Accessible by both roles with different scopes

  * ``GET /agents/:agent_id`` - Agents can read own status only, admins can read any agent

* **Admin operations**: Requires mTLS client certificate authentication

  * Full access to all management operations
  * Create/delete/update agents
  * Manage IMA and UEFI policies
  * View attestation results for any agent

The ``simple`` provider implements strict separation between agent and admin
authentication methods:

**Authentication Method Separation**

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Authorization Header
     - Authentication Path
     - Identity Type
   * - Present (Bearer token)
     - Agent path
     - ``agent`` or ``anonymous``
   * - Absent
     - Admin path (mTLS)
     - ``admin`` or ``anonymous``

**Critical Security Rule**: If an ``Authorization`` header is present in a request,
the request is **always** treated as an agent authentication attempt. There is **no
fallback** to mTLS authentication. This prevents privilege escalation attacks where
an attacker might send an invalid bearer token while having a valid mTLS certificate.

**Authorization Rules**

1. **Public actions**: Always allowed regardless of identity
2. **Agent-only actions**: Requires ``identity_type == "agent"`` AND ``identity == resource``
3. **Agent-or-admin actions**: Agent with ``identity == resource`` OR admin
4. **Admin actions**: Requires ``identity_type == "admin"``

Certificate Requirements
~~~~~~~~~~~~~~~~~~~~~~~~

The security model relies on proper certificate management:

.. list-table::
   :header-rows: 1
   :widths: 25 25 50

   * - Role
     - Authentication
     - Certificate Requirements
   * - Agent (pull mode)
     - N/A (agent is server)
     - Self-signed server cert acceptable. If CA-issued, must have Server Auth EKU only.
   * - Agent (push mode)
     - PoP bearer token
     - No client certs from trusted CA. Use PoP tokens only.
   * - Admin/Tenant
     - mTLS client cert
     - Signed by verifier's trusted CA with Client Auth EKU.

**Security Note**: Never distribute client certificates signed by the verifier's trusted
CA to agents. Agents should only authenticate using PoP tokens. If an agent had a valid
client certificate AND didn't send an Authorization header, they would be identified as
an admin.

**Pull Mode Agent Certificates**

Pull mode agents act as servers (the verifier connects to them). Their certificates have
no security relevance for authorization because:

1. Trust is established via TPM quote, not the certificate
2. The agent's certificate is added to the verifier's client-side trust store only for
   that specific connection
3. The agent never connects to the verifier as a client

Self-signed certificates are acceptable for pull mode agents.

If the pull mode agent certificate is issued by the trusted CA (instead of self-signed),
it **must have the Server Authentication EKU** (OID 1.3.6.1.5.5.7.3.1). This prevents the
certificate from being used for client authentication, which would grant admin access.

Default Configuration (Development/Testing)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the verifier is configured with ``tls_dir = generate``, it automatically creates:

* A Certificate Authority (CA)
* Server certificates for the verifier
* **Client certificates for admin operations**

The automatically generated client certificate has:

* **Common Name (CN)**: ``client``
* **Location**: ``/var/lib/keylime/cv_ca/client-cert.crt``
* **Private Key**: ``/var/lib/keylime/cv_ca/client-private.pem``

The tenant tool (used for admin operations) is configured to use this certificate by default:

.. code-block:: ini

   [tenant]
   tls_dir = default
   client_cert = default      # Uses /var/lib/keylime/cv_ca/client-cert.crt
   client_key = default       # Uses /var/lib/keylime/cv_ca/client-private.pem

**What This Means**

With default configuration:

* The verifier automatically generates all necessary certificates on startup
* The tenant tool automatically uses the generated client certificate
* Admin operations work **out-of-the-box** without manual certificate management
* This setup is suitable for **development, testing, and single-admin deployments**

Production Configuration (Multi-Admin Deployments)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For production deployments with multiple administrators, you should generate unique
certificates for each administrator.

Step 1: Generate Admin Certificates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For each administrator, generate a unique certificate:

.. code-block:: bash

   # Generate certificate for admin1
   keylime_ca -d /var/lib/keylime/cv_ca create -n admin1.example.com

   # Generate certificate for admin2
   keylime_ca -d /var/lib/keylime/cv_ca create -n admin2.example.com

Step 2: Package and Distribute Certificates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create certificate packages for distribution:

.. code-block:: bash

   # Create package for admin1
   keylime_ca -d /var/lib/keylime/cv_ca pkg -n admin1.example.com

   # This creates: admin1.example.com-pkg.zip

Distribute the certificate package securely to each administrator (encrypted email,
secure file transfer, etc.).

Step 3: Configure Tenant Tool
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each administrator should extract their certificate package and configure the tenant tool:

.. code-block:: bash

   # Extract certificate package
   unzip admin1.example.com-pkg.zip -d ~/keylime-certs/

   # Configure tenant tool
   cat > ~/.keylime/tenant.conf <<EOF
   [tenant]
   tls_dir = ~/keylime-certs/
   client_cert = admin1.example.com-cert.crt
   client_key = admin1.example.com-private.pem
   trusted_server_ca = [cacert.crt]
   EOF

Admin Operations Reference
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following operations require admin authentication (mTLS client certificate signed
by the verifier's trusted CA):

**Agent Management**

* ``GET /v3/agents`` - List all agents
* ``POST /v3/agents`` - Create/enroll a new agent
* ``GET /v3/agents/:agent_id`` - View agent details (admin can view any agent)
* ``PATCH /v3/agents/:agent_id`` - Update agent configuration
* ``DELETE /v3/agents/:agent_id`` - Delete an agent
* ``PUT /v3/agents/:agent_id/reactivate`` - Reactivate an agent
* ``PUT /v3/agents/:agent_id/stop`` - Stop agent verification

**IMA Policy Management**

* ``GET /v3/policies/ima`` - List IMA policies
* ``POST /v3/policies/ima`` - Create IMA policy
* ``GET /v3/policies/ima/:name`` - View IMA policy
* ``PATCH /v3/policies/ima/:name`` - Update IMA policy
* ``DELETE /v3/policies/ima/:name`` - Delete IMA policy

**UEFI/Measured Boot Policy Management**

* ``GET /v3/refstates/uefi`` - List UEFI reference states
* ``POST /v3/refstates/uefi`` - Create UEFI reference state
* ``GET /v3/refstates/uefi/:name`` - View UEFI reference state
* ``PATCH /v3/refstates/uefi/:name`` - Update UEFI reference state
* ``DELETE /v3/refstates/uefi/:name`` - Delete UEFI reference state

**Attestation Viewing (Push Mode)**

* ``GET /v3/agents/:agent_id/attestations`` - View all attestations for an agent
* ``GET /v3/agents/:agent_id/attestations/:index`` - View specific attestation
* ``GET /v3/agents/:agent_id/attestations/latest`` - View latest attestation

Agent-Only Operations Reference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following operations require agent authentication (PoP bearer token) and are
exclusively for agents - admins cannot access these endpoints:

**Attestation Submission (Push Mode)**

* ``POST /v3/agents/:agent_id/attestations`` - Submit attestation (own agent_id only)
* ``PATCH /v3/agents/:agent_id/attestations/:index`` - Update attestation
* ``PATCH /v3/agents/:agent_id/attestations/latest`` - Update latest attestation

**Note on Session Management**

Session operations (``POST /v3/sessions``, ``PATCH /v3/sessions/:session_id``) are
public at the authorization layer. The session controller validates the PoP response
or existing token internally. This allows agents to complete initial PoP authentication
(when they don't yet have a token) and extend existing sessions.

Agent-or-Admin Operations Reference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following operations are accessible to both agents and admins:

* ``GET /v3/agents/:agent_id`` - Agent can read own status (agent_id must match token),
  admin can read any agent

Security Considerations
~~~~~~~~~~~~~~~~~~~~~~~~

**Authentication Method Separation**

The strict separation between bearer token and mTLS authentication is a critical
security feature:

1. If an ``Authorization`` header is present, mTLS is **never** used
2. This prevents an attacker with both a valid mTLS cert and an expired/invalid
   token from falling back to admin authentication
3. Agents should **never** have client certificates signed by the trusted CA

**Certificate Validation**

The verifier validates admin mTLS certificates as follows:

1. **Certificate Trust**: The certificate must be signed by a CA trusted by the verifier
   (configured via ``trusted_client_ca``)
2. **Certificate Validity**: The certificate must not be expired or revoked
3. **EKU Check**: The certificate must have Client Authentication EKU

Registrar Authorization
~~~~~~~~~~~~~~~~~~~~~~~

The registrar uses a simpler authorization model than the verifier. Since the registrar
is primarily used for agent registration (which must be public) and administrative
queries, it has only two categories of operations:

**Public Operations (No Authentication Required)**

* ``POST /v2/agents`` - Agent registration
* ``POST /v2/agents/:agent_id`` - Agent registration (legacy endpoint)
* ``POST /v2/agents/:agent_id/activate`` - Agent activation
* ``PUT /v2/agents/:agent_id/activate`` - Agent activation (legacy endpoint)
* ``PUT /v2/agents/:agent_id`` - Agent activation (legacy endpoint)
* ``GET /version`` - Version information

**Admin Operations (Requires mTLS Client Certificate)**

* ``GET /v2/agents`` - List all registered agents
* ``GET /v2/agents/:agent_id`` - View agent registration details
* ``DELETE /v2/agents/:agent_id`` - Delete agent registration

**Registrar Security Model**

Unlike the verifier, the registrar does not use PoP bearer tokens. The security model is:

1. **Public endpoints**: Agent registration endpoints are accessible without authentication
   because agents need to register before they have any credentials
2. **Admin endpoints**: All management operations (list, view, delete) require mTLS
   client certificate authentication

**Configuration**

The registrar has its own TLS configuration and can use a completely separate CA from
the verifier. Admin operations require a client certificate signed by the CA specified
in the registrar's ``trusted_client_ca`` configuration:

.. code-block:: ini

   [registrar]
   # Use a dedicated CA for the registrar
   tls_dir = /var/lib/keylime/reg_ca
   server_key = server-private.pem
   server_cert = server-cert.crt
   trusted_client_ca = [cacert.crt]

   # Or use 'generate' to auto-generate certificates
   # tls_dir = generate

For convenience during development and testing, the default configuration shares
certificates with the verifier:

.. code-block:: ini

   [registrar]
   tls_dir = default              # Uses /var/lib/keylime/cv_ca
   server_key = default           # Uses server-private.pem
   server_cert = default          # Uses server-cert.crt
   trusted_client_ca = default    # Uses [cacert.crt]

When using the default shared configuration, admin certificates valid for the verifier
will also work for registrar operations. In production deployments with separate CAs,
administrators need certificates from each component's respective CA.

Troubleshooting
~~~~~~~~~~~~~~~

Error: "Action requires admin authentication (mTLS certificate)"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Cause**: The request doesn't have a valid mTLS client certificate.

**Solution**: Verify tenant configuration includes:

.. code-block:: ini

   [tenant]
   tls_dir = default  # Or path to certificate directory
   client_cert = default  # Or specific certificate file
   client_key = default   # Or specific key file

Ensure the certificate is signed by a CA in the verifier's ``trusted_client_ca`` list.

Error: "Action requires agent authentication (PoP token)"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Cause**: The PoP token is missing on the request header. Maybe an admin (mTLS)
is trying to access an agent-only endpoint.

**Solution**: Agent endpoints can only be accessed using PoP bearer tokens obtained
through the push attestation authentication flow. Admins should use admin endpoints
to view agent data.

Error: "Agent cannot access resource (ownership required)"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Cause**: An agent is trying to access another agent's resources.

**Solution**: Agents can only access their own resources. The agent_id in the URL
must match the agent_id associated with the bearer token.

Verifying Certificate EKU
^^^^^^^^^^^^^^^^^^^^^^^^^^

To check the Extended Key Usage of a certificate:

.. code-block:: bash

   openssl x509 -in /var/lib/keylime/cv_ca/client-cert.crt -noout -text | grep -A1 "Extended Key Usage"
   # Should show: TLS Web Client Authentication

