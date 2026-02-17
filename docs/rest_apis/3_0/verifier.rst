Verifier
~~~~~~~~

Push-Model Attestation Endpoints
"""""""""""""""""""""""""""""""""

These endpoints implement the two-phase push-model attestation protocol. Agents
use these endpoints to submit attestation capabilities and evidence. Administrators
can use the GET endpoints to view attestation results.

For details on authentication requirements, see :doc:`../../user_guide/authentication`.

.. http:post:: /v3/agents/{agent_id}/attestations

    Phase 1: Submit attestation capabilities and receive a challenge.

    The agent sends its supported evidence types, cryptographic algorithms, and
    attestation key. The verifier selects parameters and returns a challenge nonce
    for TPM quote generation.

    :param agent_id: UUID of the agent
    :type agent_id: string

    **Authentication**: PoP bearer token (agent-only)

    **Example request**:

    .. sourcecode:: json

        {
          "data": {
            "type": "attestation",
            "attributes": {
              "evidence_supported": [
                {
                  "evidence_class": "certification",
                  "evidence_type": "tpm_quote",
                  "capabilities": {
                    "signature_schemes": ["rsassa"],
                    "hash_algorithms": ["sha256", "sha384", "sha512"],
                    "available_subjects": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
                    "certification_keys": [
                      {
                        "key_class": "asymmetric",
                        "key_algorithm": "rsa",
                        "key_size": 2048,
                        "server_identifier": "ak",
                        "allowable_signature_schemes": ["rsassa"],
                        "allowable_hash_algorithms": ["sha256", "sha384", "sha512"],
                        "public": "<base64-encoded AK public key>"
                      }
                    ],
                    "component_version": "2.0",
                    "evidence_version": "1.0"
                  }
                },
                {
                  "evidence_class": "log",
                  "evidence_type": "ima_log",
                  "capabilities": {
                    "entry_count": 1024,
                    "supports_partial_access": true,
                    "appendable": true,
                    "formats": ["text/plain"],
                    "component_version": "1.0",
                    "evidence_version": "1.0"
                  }
                }
              ],
              "system_info": {
                "boot_time": "2024-01-15T10:30:00Z"
              }
            }
          }
        }

    **Example response** (201 Created):

    .. sourcecode:: json

        {
          "data": {
            "type": "attestation",
            "id": "0",
            "attributes": {
              "stage": "awaiting_evidence",
              "evidence_requested": [
                {
                  "evidence_class": "certification",
                  "evidence_type": "tpm_quote",
                  "chosen_parameters": {
                    "challenge": "<base64-encoded nonce>",
                    "signature_scheme": "rsassa",
                    "hash_algorithm": "sha256",
                    "selected_subjects": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
                    "certification_key": {
                      "key_class": "asymmetric",
                      "key_algorithm": "rsa",
                      "key_size": 2048,
                      "server_identifier": "ak"
                    }
                  }
                },
                {
                  "evidence_class": "log",
                  "evidence_type": "ima_log",
                  "chosen_parameters": {
                    "starting_offset": 0,
                    "entry_count": 1024,
                    "format": "text/plain"
                  }
                }
              ],
              "system_info": {
                "boot_time": "2024-01-15T10:30:00Z"
              },
              "capabilities_received_at": "2024-01-15T10:30:00.123456Z",
              "challenges_expire_at": "2024-01-15T10:35:00.123456Z"
            },
            "links": {
              "self": "/v3/agents/{agent_id}/attestations/0"
            }
          }
        }

    :<json string data.type: Must be ``"attestation"``
    :<json array data.attributes.evidence_supported: List of evidence types the agent can produce
    :<json string evidence_supported[].evidence_class: ``"certification"`` or ``"log"``
    :<json string evidence_supported[].evidence_type: ``"tpm_quote"``, ``"ima_log"``, or ``"uefi_log"``
    :<json object evidence_supported[].capabilities: Capabilities for this evidence type
    :<json object data.attributes.system_info: System information (e.g. boot time)
    :>json string data.id: Attestation index (auto-incremented per agent)
    :>json string data.attributes.stage: ``"awaiting_evidence"``
    :>json array data.attributes.evidence_requested: Evidence the verifier wants the agent to provide
    :>json string evidence_requested[].chosen_parameters.challenge: Base64-encoded challenge nonce for TPM quote
    :>json string data.attributes.capabilities_received_at: ISO 8601 timestamp
    :>json string data.attributes.challenges_expire_at: Deadline for evidence submission
    :>json string data.links.self: URL to this attestation resource

    :statuscode 201: Attestation created, challenge issued
    :statuscode 400: Invalid request body
    :statuscode 403: Attestations disabled for this agent (timeout or previous failure)
    :statuscode 404: Agent not found
    :statuscode 409: Concurrent attestation creation attempt
    :statuscode 422: Invalid capabilities data
    :statuscode 429: Rate limited (attestation interval not elapsed). Includes ``Retry-After`` header
    :statuscode 503: Previous attestation still being verified. Includes ``Retry-After`` header


.. http:patch:: /v3/agents/{agent_id}/attestations/latest

    Phase 2: Submit attestation evidence for the latest attestation.

    The agent sends the TPM quote, PCR values, and event logs generated using the
    challenge nonce from Phase 1. The verifier accepts the evidence and verifies it
    asynchronously.

    :param agent_id: UUID of the agent
    :type agent_id: string

    **Authentication**: PoP bearer token (agent-only)

    **Example request**:

    .. sourcecode:: json

        {
          "data": {
            "type": "attestation",
            "attributes": {
              "evidence_collected": [
                {
                  "evidence_class": "certification",
                  "evidence_type": "tpm_quote",
                  "data": {
                    "subject_data": {
                      "0": "<PCR 0 value>",
                      "1": "<PCR 1 value>"
                    },
                    "message": "<base64-encoded TPM quote>",
                    "signature": "<base64-encoded quote signature>"
                  }
                },
                {
                  "evidence_class": "log",
                  "evidence_type": "ima_log",
                  "data": {
                    "entry_count": 512,
                    "entries": "<base64-encoded or raw IMA log entries>"
                  }
                }
              ]
            }
          }
        }

    **Example response** (202 Accepted):

    .. sourcecode:: json

        {
          "data": {
            "type": "attestation",
            "id": "0",
            "attributes": {
              "stage": "evaluating_evidence",
              "evidence": [
                {
                  "evidence_class": "certification",
                  "evidence_type": "tpm_quote",
                  "capabilities": {},
                  "chosen_parameters": {},
                  "data": {
                    "message": "<base64-encoded TPM quote>",
                    "signature": "<base64-encoded quote signature>",
                    "subject_data": {}
                  }
                }
              ],
              "system_info": {
                "boot_time": "2024-01-15T10:30:00Z"
              },
              "capabilities_received_at": "2024-01-15T10:30:00.123456Z",
              "challenges_expire_at": "2024-01-15T10:35:00.123456Z",
              "evidence_received_at": "2024-01-15T10:31:00.123456Z"
            },
            "links": {
              "self": "/v3/agents/{agent_id}/attestations/0"
            }
          },
          "meta": {
            "seconds_to_next_attestation": 45
          }
        }

    :<json string data.type: Must be ``"attestation"``
    :<json array data.attributes.evidence_collected: List of evidence items
    :<json string evidence_collected[].evidence_class: ``"certification"`` or ``"log"``
    :<json string evidence_collected[].evidence_type: Type of evidence (must match what was requested)
    :<json object evidence_collected[].data: Evidence data (format depends on evidence type)
    :>json string data.attributes.stage: ``"evaluating_evidence"`` (verification in progress)
    :>json array data.attributes.evidence: Evidence items with capabilities, parameters, and data
    :>json string data.attributes.evidence_received_at: ISO 8601 timestamp when evidence was received
    :>json int meta.seconds_to_next_attestation: Suggested wait before starting the next attestation cycle

    :statuscode 202: Evidence accepted, verification in progress
    :statuscode 400: Invalid evidence format
    :statuscode 403: Evidence already submitted, attestation is not the latest, or challenges expired
    :statuscode 404: Agent or attestation not found
    :statuscode 410: Attestation no longer exists
    :statuscode 503: No available worker processes. Includes ``Retry-After`` header


.. http:patch:: /v3/agents/{agent_id}/attestations/{index}

    Submit attestation evidence for a specific attestation by index.

    Behaves identically to ``PATCH /v3/agents/{agent_id}/attestations/latest``
    but targets a specific attestation index. Evidence can only be submitted for
    the latest attestation.

    :param agent_id: UUID of the agent
    :type agent_id: string
    :param index: Attestation index
    :type index: integer

    **Authentication**: PoP bearer token (agent-only)

    :statuscode 202: Evidence accepted
    :statuscode 403: Not the latest attestation, evidence already submitted, or challenges expired
    :statuscode 404: Agent or attestation not found


.. http:get:: /v3/agents/{agent_id}/attestations

    List all attestations for an agent.

    :param agent_id: UUID of the agent
    :type agent_id: string

    **Authentication**: mTLS (admin) or PoP bearer token (own agent only)

    **Example response**:

    .. sourcecode:: json

        {
          "data": [
            {
              "type": "attestation",
              "id": "1",
              "attributes": {
                "stage": "verification_complete",
                "evaluation": "pass",
                "evidence": [],
                "system_info": {
                  "boot_time": "2024-01-15T10:30:00Z"
                },
                "capabilities_received_at": "2024-01-15T10:30:00.123456Z",
                "challenges_expire_at": "2024-01-15T10:35:00.123456Z",
                "evidence_received_at": "2024-01-15T10:31:00.123456Z",
                "verification_completed_at": "2024-01-15T10:32:00.123456Z"
              },
              "links": {
                "self": "/v3/agents/{agent_id}/attestations/1"
              }
            },
            {
              "type": "attestation",
              "id": "0",
              "attributes": {
                "stage": "verification_complete",
                "evaluation": "pass",
                "evidence": [],
                "system_info": {},
                "capabilities_received_at": "2024-01-15T10:25:00.123456Z",
                "challenges_expire_at": "2024-01-15T10:30:00.123456Z",
                "evidence_received_at": "2024-01-15T10:26:00.123456Z",
                "verification_completed_at": "2024-01-15T10:27:00.123456Z"
              },
              "links": {
                "self": "/v3/agents/{agent_id}/attestations/0"
              }
            }
          ]
        }

    :>json array data: List of attestation resources
    :>json string data[].id: Attestation index
    :>json string data[].attributes.stage: ``"awaiting_evidence"``, ``"evaluating_evidence"``, or ``"verification_complete"``
    :>json string data[].attributes.evaluation: ``"pending"``, ``"pass"``, or ``"fail"``
    :>json string data[].attributes.failure_reason: ``"broken_evidence_chain"`` or ``"policy_violation"`` (only when evaluation is ``"fail"``)

    :statuscode 200: Success
    :statuscode 404: Agent not found


.. http:get:: /v3/agents/{agent_id}/attestations/latest

    Get the latest attestation for an agent.

    :param agent_id: UUID of the agent
    :type agent_id: string

    **Authentication**: mTLS (admin) or PoP bearer token (own agent only)

    **Example response**:

    .. sourcecode:: json

        {
          "data": {
            "type": "attestation",
            "id": "1",
            "attributes": {
              "stage": "verification_complete",
              "evaluation": "pass",
              "failure_reason": null,
              "evidence": [
                {
                  "evidence_class": "certification",
                  "evidence_type": "tpm_quote",
                  "capabilities": {},
                  "chosen_parameters": {},
                  "data": {
                    "message": "<base64-encoded TPM quote>",
                    "signature": "<base64-encoded signature>",
                    "subject_data": {}
                  }
                }
              ],
              "system_info": {
                "boot_time": "2024-01-15T10:30:00Z"
              },
              "capabilities_received_at": "2024-01-15T10:30:00.123456Z",
              "challenges_expire_at": "2024-01-15T10:35:00.123456Z",
              "evidence_received_at": "2024-01-15T10:31:00.123456Z",
              "verification_completed_at": "2024-01-15T10:32:00.123456Z"
            },
            "links": {
              "self": "/v3/agents/{agent_id}/attestations/1"
            }
          }
        }

    :>json string data.attributes.stage: Current stage of the attestation
    :>json string data.attributes.evaluation: ``"pending"``, ``"pass"``, or ``"fail"``
    :>json string data.attributes.failure_reason: ``null``, ``"broken_evidence_chain"``, or ``"policy_violation"``
    :>json array data.attributes.evidence: Evidence items with full data
    :>json string data.attributes.capabilities_received_at: When capabilities were received
    :>json string data.attributes.challenges_expire_at: When challenges expire
    :>json string data.attributes.evidence_received_at: When evidence was received (``null`` if still awaiting)
    :>json string data.attributes.verification_completed_at: When verification completed (``null`` if still in progress)

    :statuscode 200: Success
    :statuscode 404: Agent not found or no attestations exist


.. http:get:: /v3/agents/{agent_id}/attestations/{index}

    Get a specific attestation by index.

    :param agent_id: UUID of the agent
    :type agent_id: string
    :param index: Attestation index
    :type index: integer

    **Authentication**: mTLS (admin) or PoP bearer token (own agent only)

    Response format is identical to ``GET /v3/agents/{agent_id}/attestations/latest``.

    :statuscode 200: Success
    :statuscode 404: Agent or attestation not found


Session Endpoints
"""""""""""""""""

These endpoints manage PoP (Proof of Possession) authentication sessions for
push-model agents. Sessions are required before an agent can submit attestations.

.. http:post:: /v3/sessions

    Create a new authentication session.

    The verifier generates a challenge nonce that the agent must sign using its
    TPM attestation key to prove possession.

    **Authentication**: None (public endpoint)

    **Example request**:

    .. sourcecode:: json

        {
          "data": {
            "type": "session",
            "attributes": {
              "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
              "authentication_supported": [
                {
                  "authentication_class": "pop",
                  "authentication_type": "tpm_pop"
                }
              ]
            }
          }
        }

    **Example response** (200 OK):

    .. sourcecode:: json

        {
          "data": {
            "type": "session",
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "attributes": {
              "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
              "authentication_requested": [
                {
                  "authentication_class": "pop",
                  "authentication_type": "tpm_pop",
                  "chosen_parameters": {
                    "challenge": "<base64-encoded nonce>"
                  }
                }
              ],
              "created_at": "2024-01-15T10:30:00.123456Z",
              "challenges_expire_at": "2024-01-15T10:31:00.123456Z"
            }
          }
        }

    :<json string data.attributes.agent_id: UUID of the agent requesting a session
    :<json array data.attributes.authentication_supported: Supported authentication methods
    :>json string data.id: Session UUID
    :>json string data.attributes.challenges_expire_at: Deadline for submitting the PoP response

    :statuscode 200: Session created
    :statuscode 400: Missing or invalid agent_id
    :statuscode 429: Rate limited. Includes ``Retry-After`` header


.. http:patch:: /v3/sessions/{session_id}

    Submit Proof of Possession response to complete authentication.

    The agent signs the challenge nonce from the session creation response using
    ``TPM2_Certify`` and submits the result. If valid, the verifier issues a bearer
    token for subsequent API calls.

    :param session_id: UUID of the session
    :type session_id: string

    **Authentication**: None (public endpoint; validates PoP internally)

    **Example request**:

    .. sourcecode:: json

        {
          "data": {
            "type": "session",
            "attributes": {
              "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
              "authentication_provided": [
                {
                  "authentication_class": "pop",
                  "authentication_type": "tpm_pop",
                  "data": {
                    "message": "<base64-encoded AK attest structure>",
                    "signature": "<base64-encoded AK signature>"
                  }
                }
              ]
            }
          }
        }

    **Example response** (200 OK, authentication passed):

    .. sourcecode:: json

        {
          "data": {
            "type": "session",
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "attributes": {
              "agent_id": "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
              "evaluation": "pass",
              "token": "550e8400-e29b-41d4-a716-446655440000.<secret>",
              "authentication": [
                {
                  "authentication_class": "pop",
                  "authentication_type": "tpm_pop",
                  "chosen_parameters": {
                    "challenge": "<base64-encoded nonce>"
                  },
                  "data": {
                    "message": "<base64-encoded AK attest>",
                    "signature": "<base64-encoded AK signature>"
                  }
                }
              ],
              "created_at": "2024-01-15T10:30:00.123456Z",
              "challenges_expire_at": "2024-01-15T10:31:00.123456Z",
              "response_received_at": "2024-01-15T10:30:30.123456Z",
              "token_expires_at": "2024-01-15T11:30:00.123456Z"
            }
          }
        }

    :>json string data.attributes.evaluation: ``"pass"`` or ``"fail"``
    :>json string data.attributes.token: Bearer token for subsequent requests (only on ``"pass"``)
    :>json string data.attributes.token_expires_at: Token expiration time (only on ``"pass"``)

    :statuscode 200: PoP response processed (check ``evaluation`` field for result)
    :statuscode 400: Missing or invalid request body
    :statuscode 401: PoP verification failed
    :statuscode 404: Session not found


Attestation Stages and Evaluations
"""""""""""""""""""""""""""""""""""

Each attestation progresses through the following stages:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Stage
     - Description
   * - ``awaiting_evidence``
     - Capabilities received, challenge issued, waiting for evidence
   * - ``evaluating_evidence``
     - Evidence received, verification in progress
   * - ``verification_complete``
     - Verification finished, see ``evaluation`` for result

The ``evaluation`` field indicates the verification result:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Evaluation
     - Description
   * - ``pending``
     - Verification not yet complete
   * - ``pass``
     - Evidence verified successfully
   * - ``fail``
     - Evidence verification failed (see ``failure_reason``)

When an attestation fails, the ``failure_reason`` field provides the cause:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Failure Reason
     - Description
   * - ``broken_evidence_chain``
     - TPM quote signature invalid or evidence integrity check failed
   * - ``policy_violation``
     - Evidence is valid but violates the configured attestation policy
