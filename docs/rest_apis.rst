==========
Rest API's
==========
All Keylime APIs use `REST (Representational State Transfer)`.

Check the :ref:`Changelog` section for the differences between versions

.. toctree::
   :maxdepth: 2
   :caption: API versions

   rest_apis/2_1/2_1.rst
   rest_apis/2_2/2_2.rst
   rest_apis/2_3/2_3.rst
   rest_apis/2_4/2_4.rst

Changelog
_________

Changes from v2.3 to v2.4
~~~~~~~~~~~~~~~~~~~~~~~~~
API version 2.4 was first implemented in Keylime 7.13.0.

* Added `POST /v2.4/verify/evidence` experimental endpoint to the verifier

Changes from v2.2 to v2.3
~~~~~~~~~~~~~~~~~~~~~~~~~
API version 2.3 was first implemented in Keylime 7.12.0.

* Added `GET /v2.3/mbpolicies/{name}` endpoint to the verifier
* Added `POST /v2.3/mbpolicies/{name}` endpoint to the verifier
* Added `PUT /v2.3/mbpolicies/{name}` endpoint to the verifier
* Added `DELETE /v2.3/mbpolicies/{name}` endpoint to the verifier
* Added `GET /version` endpoint to the registrar

Changes from v2.1 to v2.2
~~~~~~~~~~~~~~~~~~~~~~~~~
API version 2.2 was first implemented in Keylime 7.11.0.

* Added `GET /v2.2/verify/identity` endpoint to the verifier
* Added `GET /v2.2/agent/info` endpoint to the agent

Changes from v2.0 to v2.1
~~~~~~~~~~~~~~~~~~~~~~~~~
API version 2.1 was first implemented in Keylime 6.4.0.

 * Added `ak_tpm` field to `POST /v2.1/agents/{agent_id:UUID}` in verifier.
 * Added `mtls_cert` field to `POST /v2.1/agents/{agent_id:UUID}` in verifier.
 * Removed `vmask` parameter from `GET /v2.1/quotes/integrity` in agent

This removed the requirement for the verifier to connect to the registrar.

Changes from v1.0 to v2.0
~~~~~~~~~~~~~~~~~~~~~~~~~
API version 2.0 was first implemented in Keylime 6.3.0.

 * Added mTLS authentication to agent endpoints.
 * Added `supported_version` field to `POST /v2.0/agents/{agent_id:UUID}` in verifier.
 * Added `mtls_cert` field to `POST/GET /v2.0/agents/{agent_id:UUID}` in registrar.
 * Added `/version` endpoint to agent. Note that this endpoint is not implemented by all agents.
 * Dropped zlib encryption for `quote` field data in `GET /v2.0/quotes/integrity`/`GET /v2.0/quotes/identity`.

RESTful API for Keylime
-----------------------
Keylime API is versioned. More information can be found here: https://github.com/keylime/enhancements/blob/master/45_api_versioning.md

.. warning::
    API version 1.0 will no longer be officially supported starting with Keylime 6.4.0.

General responses
~~~~~~~~~~~~~~~~~~~

.. http:any:: /

    Generic fields in responses

    :>json int code: HTTP status code
    :>json string status: textual context of that status
    :>json object results: Holds the actual data.

