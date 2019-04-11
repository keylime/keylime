==========
Rest API's
==========

https://docs.readthedocs.io/en/stable/api/v2.html

All Keylime APIs use `REST (Representational State Transfer)`.

Authentication and authorization
--------------------------------

Not yet implemented

tenant -> cloud verifier (CV)
++++++++++++++++++++++++++++

.. http:get::  /v2/agents/{agent_id:UUID}

    Get status of agent `agent_id` from CV

    **Example request**:

    .. prompt:: bash $

        curl https://readthedocs.org/api/v2/project/?slug=pip

    **Example response**:

    .. sourcecode:: js

        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [PROJECTS]
        }

    :>json string next: URI for next set of Projects.
    :>json string previous: URI for previous set of Projects.
    :>json integer count: Total number of Projects.
    :>json array results: Array of ``Project`` objects.

    :query string slug: Narrow the results by matching the exact project slug

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
            “ima_whitelist” : json,
            “accept_tpm_hash_algs”: list,
            “accept_tpm_encryption_algs”: list,
            “accept_tpm_signing_algs”: list,
        }

        :>json string next: URI for next set of Projects.
        :>json string previous: URI for previous set of Projects.
        :>json integer count: Total number of Projects.
        :>json array results: Array of ``Project`` objects.

        :query string slug: Narrow the results by matching the exact project slug

        **Example request**:

        .. prompt:: bash $

            curl https://readthedocs.org/api/v2/project/?slug=pip
