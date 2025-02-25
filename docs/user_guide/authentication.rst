Authentication
--------------
Most API interactions are secured using mTLS connections. By default there are two CAs involved,
but the components can be configured to accommodate more complex setups.

(The revocation process also uses a CA, but this is different to those CAs)

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

