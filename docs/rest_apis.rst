==========
Rest API's
==========

https://docs.readthedocs.io/en/stable/api/v2.html

All Keylime APIs use `REST (Representational State Transfer)`.

Authentication and authorization
--------------------------------

Not yet implemented

RESTful API for Keylime (v2)
----------------------------

Cloud verifier (CV)
~~~~~~~~~~~~~~~~~~~

.. http:get::  /v2/agents/{agent_id:UUID}

    Get status of agent `agent_id` from CV

.. http:post::  /v2/agents/{agent_id:UUID}

    Add new agent `instance_id` to CV

    **Requires JSON Body**:

    .. sourcecode:: js

        {
          “v” : key,
          “ip” : ipaddr,
          “port” : int,
          “operational_state” : int,
          “public_key” : key,
          “tpm_policy” : json,
          “vtpm_policy” : json,
          “metadata” : json,
          “allowlist” : json,
          “accept_tpm_hash_algs”: list,
          “accept_tpm_encryption_algs”: list,
          “accept_tpm_signing_algs”: list,
        }

        .. http:delete::  /v2/agents/{agent_id:UUID}

           Terminate instance `agent_id`

.. http:put::  /v2/agents/{agent_id:UUID}/reactivate

    Start agent `agent_id`` (for an already bootstrapped `agent_id` node)

.. http:put::  /v2/agents/{agent_id:UUID}/stop

    Stop cv polling on `agent_id`, but don’t delete (for an already started `agent_id`)

Cloud Agent
~~~~~~~~~~~

.. http:get::  /v2/keys/pubkey

    Retrieves agents public key

.. http:post::  /v2/keys/vkey

    Send `v_key` to node

    **Requires JSON Body**:

    .. sourcecode:: js

      {
        “encrypted_key”: key,
      }

.. http:post::  /v2/keys/ukey

    Send `u_key` to node (with optional payload)

    **Requires JSON Body**:

    .. sourcecode:: js

      {
        “auth_tag” : hmac,
        “encrypted _key”: key,
        “payload”: b64, (opt)
      }

.. http:get::  /v2/keys/verify

    Get confirmation of bootstrap key derivation

    **Requires query parameters:**

    .. sourcecode:: js

      challenge : string

.. http:get::  /v2/quotes/integrity

    Get integrity quote from node

    **Required parameters:**

    .. sourcecode:: js

      nonce : int
      mask : bitmask
      vmask : bitmask
      partial : bool

    Example:

    .. sourcecode:: bash

      /v2/quotes/integrity?nonce=#&mask=#&vmask=#&partial=#

.. http:get::  /v2/quotes/identity

    Get identity quote from node

    **Required parameters:**

    .. sourcecode:: js

      nonce : int

    Example:

    .. sourcecode:: bash

      /v2/quotes/identity?nonce=#

Cloud Registrar
~~~~~~~~~~~~~~~

.. http:get::  /v2/agents/

    Get ordered list of registered agents

.. http:get::  /v2/agents/{agent_id:UUID}

    Get AIK of agent `agent_id`

.. http:post::  /v2/agents/{agent_id:UUID}

    Add agent `agent_id` to registrar

    **Requires JSON Body**:

    .. sourcecode:: js

      {
        “ek” : key,
        “ekcert” : cert,
        “aik” : key,
        “tpm_version”: TPM version,
        “aik_name” : key name, (tpm2)
        “ek_tpm” : TPM-format key (tpm2)
      }

.. http:delete::  /v2/agents/{agent_id:UUID}

    Remove agent `agent_id` from registrar


.. http:put::  /v2/agents/{agent_id:UUID}/activate

    Activate physical agent `agent_id`

    **Requires JSON Body**:

    .. sourcecode:: js

    {
      “auth_tag” : hmac,
    }

.. http:put::  /v2/agents/{agent_id:UUID}/vactivate

    Activate virtual (vTPM) agent `agent_id`

    **Requires JSON Body**:

    .. sourcecode:: js

    {
      “deepquote” : b64,
    }

Tenant WebApp
~~~~~~~~~~~~~

.. http:get::  /v2/agents/

    Get ordered list of registered agents

.. http:get::  /v2/agents/{agent_id:UUID}

    Get list of registered agents

.. http:put::  /v2/agents/{agent_id:UUID}

    Start agent `agent_id` (For an already bootstrapped `agent_id` agent)

.. http:post::  /v2/agents/{agent_id:UUID}

    Add agent `agent_id` to registrar

    **Requires JSON Body**:

    .. sourcecode:: js

      {
        “ip” : ipaddr,
        “keyfile_data” : base64,
        “keyfile_name” : string, (opt)
        “file_data” : base64,
        “file_name” : string, (opt)
        “ca_dir” : string,
        “ca_dir_pw” : string,
        “include_dir_data” : base64,
        “include_dir_name” : string,
      }

.. http:get::  /v2/logs/

          Get terminal log data

.. http:get::  /v2/logs/{logType:string}

          Get terminal log data for given logType

          Optional query parameters:

          .. sourcecode:: bash

            pos : int, (opt)

          Example:

          .. sourcecode:: bash

            /v2/logs/tenant?pos=#

RESTful API Responses for Keylime (v2)
--------------------------------------
