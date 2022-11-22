==========
Rest API's
==========
All Keylime APIs use `REST (Representational State Transfer)`.

Authentication
--------------
Most API interactions are secured using mTLS connections.
There are up to three different CAs involved.
(The revocation process also uses a CA, but this is a different to those CAs)

Verifier CA (CV CA)
~~~~~~~~~~~~~~~~~~~
This CA is used by the verifier to authenticate connections to it.
The tenant requires a certificate from this CA to add/delete/list agents at the CV.

Registrar CA
~~~~~~~~~~~~
This CA is used by the registrar to authenticate connections to it.
The tenant and the verifier require certificate from this CA to get or delete agent information from the registrar.
By default it is the same CA as the CV CA.

Note that the API endpoints from the registrar for the agent are unprotected by design.

Agent Keylime CA
~~~~~~~~~~~~~~~~
The agent runs a HTTPS server and provides it's certificate to the registrar (`mtls_cert`).
All connections done to the agent are verified against the CA specified in the `keylime_ca` option.
This ensures that only trusted systems can interact with the agents.
By default the CV CA is used, but the CA certificate (`cacert.crt`) needs to be copied to the agents.

Registrar, tenant and verifier can configure this CA separately using the `agent_mtls_*` options.

RESTful API for Keylime (v2.1)
----------------------------
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


Cloud verifier (CV)
~~~~~~~~~~~~~~~~~~~

.. http:get::  /v2.1/agents/{agent_id:UUID}

    Get status of agent `agent_id` from CV

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "operational_state": 7,
            "v": "yyNnlWwFRz1ZUzSe2YEpz9A5urtv6oywgttTF7VbBP4=",
            "ip": "127.0.0.1",
            "port": 9002,
            "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
            "vtpm_policy": "{\"23\": [\"ffffffffffffffffffffffffffffffffffffffff\", \"0000000000000000000000000000000000000000\"], \"15\": [\"0000000000000000000000000000000000000000\"], \"mask\": \"0x808000\"}",
            "meta_data": "{}",
            "has_mb_refstate": 0,
            "has_ima_policy": 0,
            "accept_tpm_hash_algs": [
              "sha512",
              "sha384",
              "sha256",
              "sha1"
            ],
            "accept_tpm_encryption_algs": [
              "ecc",
              "rsa"
            ],
            "accept_tpm_signing_algs": [
              "ecschnorr",
              "rsassa"
            ],
            "hash_alg": "sha256",
            "enc_alg": "rsa",
            "sign_alg": "rsassa",
            "verifier_id": "default",
            "verifier_ip": "127.0.0.1",
            "verifier_port": 8881,
            "severity_level": 6,
            "last_event_id": "qoute_validation.quote_validation"
          }
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json int operational_state: Current state of the agent in the CV. Defined in https://github.com/keylime/keylime/blob/master/keylime/common/states.py
    :>json string v: V key for payload base64 encoded. Decoded length is 32 bytes
    :>json string ip: Agents contact ip address for the CV
    :>json string port: Agents contact port for the CV
    :>json string tpm_policy: Static PCR policy and mask for TPM
    :>json string vtpm_policy: Static PCR policy and mask for vTPM
    :>json string meta_data: Metadata about the agent. Normally contains certificate information if a CA is used.
    :>json int allowlist_len: Length of the allowlist.
    :>json int mb_refstate_len: 1 if a measured boot refstate was provided via tenant, 0 otherwise.
    :>json int mb_ima_policy: 1 if an IMA policy (allowlist and excludelist) was provided via tenant, 0 otherwise.
    :>json list[string] accept_tpm_hash_algs: Accepted TPM hashing algorithms. sha1 must be enabled for IMA validation to work.
    :>json list[string] accept_tpm_encryption_algs: Accepted TPM encryption algorithms.
    :>json list[string] accept_tpm_signing_algs: Accepted TPM signing algorithms.
    :>json string hash_alg: Used hashing algorithm.
    :>json string enc_alg: Used encryption algorithm.
    :>json string sign_alg: Used signing algorithm.
    :>json string verifier_id: Name of the verifier that is used. (Only important if multiple verifiers are used)
    :>json string verifier_ip: IP of the verifier that is used.
    :>json int verifier_port: Port of the verifier that is used.
    :>json int severity_level: Severity level of the agent. Might be `null`. Levels are the numeric representation of the severity labels.
    :>json string last_event_id: ID of the last revocation event. Might be `null`.


.. http:post::  /v2.1/agents/{agent_id:UUID}

    Add new agent `instance_id` to CV.

    **Example request**:

    .. sourcecode:: json

        {
          "v": "3HZMmIEc6yyjfoxdCwcOgPk/6X1GuNG+tlCmNgqBM/I=",
          "cloudagent_ip": "127.0.0.1",
          "cloudagent_port": 9002,
          "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
          "vtpm_policy": "{\"23\": [\"ffffffffffffffffffffffffffffffffffffffff\", \"0000000000000000000000000000000000000000\"], \"15\": [\"0000000000000000000000000000000000000000\"], \"mask\": \"0x808000\"}",
          "allowlist": "{}",
          "mb_refstate": "null",
          "ima_sign_verification_keys": "[]",
          "metadata": "{\"cert_serial\": 71906672046699268666356441515514540742724395900, \"subject\": \"/C=US/ST=MA/L=Lexington/O=MITLL/OU=53/CN=D432FBB3-D2F1-4A97-9EF7-75BD81C00000\"}",
          "revocation_key": "-----BEGIN PRIVATE KEY----- (...) -----END PRIVATE KEY-----\n",
          "accept_tpm_hash_algs": [
            "sha512",
            "sha384",
            "sha256",
            "sha1"
          ],
          "accept_tpm_encryption_algs": [
            "ecc",
            "rsa"
          ],
          "accept_tpm_signing_algs": [
            "ecschnorr",
            "rsassa"
          ],
          "supported_version": "2.0"
        }



    :<json string v: V key for payload base64 encoded. Decoded length is 32 bytes.
    :<json string cloudagent_ip: Agents contact ip address for the CV.
    :<json string cloudagent_port: Agents contact port for the CV.
    :<json string tpm_policy: Static PCR policy and mask for TPM. Is a string encoded dictionary that also includes a `mask` for which PCRs should be included in a quote.
    :<json string vtpm_policy: Static PCR policy and mask for vTPM. Same as `tpm_policy`.
    :<json string allowlist: Allowlist JSON object string encoded.
    :<json string mb_refstate: Measured boot reference state policy.
    :<json string ima_sign_verification_keys: IMA signature verification public keyring JSON object string encoded.
    :<json string metadata: Metadata about the agent. Contains `cert_serial` and `subject` if a CA is used with the tenant.
    :<json string revocation_key: Key which is used to sign the revocation message of the agent.
    :<json list[string] accept_tpm_hash_algs: Accepted TPM hashing algorithms. sha1 must be enabled for IMA validation to work.
    :<json list[string] accept_tpm_encryption_algs: Accepted TPM encryption algorithms.
    :<json list[string] accept_tpm_signing_algs: Accepted TPM signing algorithms.
    :<json string supported_version: supported API version of the agent. `v` prefix must not be included.

.. http:delete::  /v2.1/agents/{agent_id:UUID}

    Terminate instance `agent_id`.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {}
        }


.. http:put::  /v2.1/agents/{agent_id:UUID}/reactivate

    Start agent `agent_id` (for an already bootstrapped `agent_id` node)

.. http:put::  /v2.1/agents/{agent_id:UUID}/stop

    Stop cv polling on `agent_id`, but don’t delete (for an already started `agent_id`).
    This will make the agent verification fail.

Cloud Agent
~~~~~~~~~~~

.. http:get::  /v2.1/keys/pubkey

    Retrieves agents public key.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "pubkey": "-----BEGIN PUBLIC KEY----- (...) -----END PUBLIC KEY-----\n"
          }
        }

    :>json string pubkey: Public rsa key of the agent used for encrypting V and U key.

.. http:get::  /version

    Returns what API version the agent supports. This endpoint might not be implemented by all agents.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "supported_version": "2.0"
          }
        }

    :>json string supported_version: The latest version the agent supports.

.. http:post::  /v2.1/keys/vkey

    Send `v_key` to node.

    **Example request**:

    .. sourcecode:: json

      {
        "encrypted_key": "MN/F33jjuLiIuRH8fF7pMtw6Hoe2KG10zg+/xuuZLa5d1WB2aR6feVCwknZDe/dhG51yB0tKau8fCNUz8KMxyWoFkalIY4vVG6DNpLouDjb+vMvI6RmVmCBwO5zx6R802wK2z2yUbcn11TU/k2zHq34CNFIgI5pQu7cnLMzCLW6NLEp8N0IOQL6D+uV9emkheJH1g40xYwUaKoABWjZeaJN5dvKwbkpIf2m+CROmCNPCidh87J0g7BENUvlSUO1FPfRjch4kyxLrp+aMu9zmzF/tZErh1zk+nUamtrgl25pEImw+Cn9RIVTd6fBkmzlGzch5foAqZCyZ0AhQ0ONuWw==",
      }

    :<json string encrypted_key: V key encrypted with agents public key base64 encoded.

.. http:post::  /v2.1/keys/ukey

    Send `u_key` to node (with optional payload)

    **Example request**:

    .. sourcecode:: json

      {
        "auth_tag" : "3876c08b30c16c4140ee04300bb4262bbcc9034d8a2ed8c90784f13b484a570bf9da3d5c372141bd16d85de05c4c7cce",
        "encrypted_key": "iAckMZgZc8r43pF0iW8iwwAorD+rvnvF7AShhlz6+am+ryqW+907UynOrWrIrAseyVRE7ouHpr547gnwfF7oKeBFlEdWnE6FbQl9o6tk86BzQy3PImBLxJD/y/MmSuNR5pGQwZCueKI0ji3Nqq6heOgSvnMRC0PHgyumOsYiAnbDNyryvfwO4HsqdqMcEsBu1IVzU3EtJWhfQ8i/UpvHy6Jq4bBh+mw5HZwmK93bmsLXNKgjPWAicsCZINUAPVMCUL7dcDd4zijsBxMxiZF7Js7V25wKKFer2zqKsE5omLy9sKotFfWjgaROPLrKXxuDgNmlONJnD0btLZBa9T+mmA==",
        "payload": "WcXpUr4G9yfvVaojNx6K2XZuDYRkFoZQhHrvZB+TKZqsq41g"
      }

    :<json string auth_tag: HMAC calculated with K key as key and UUID as data, using SHA-384 as the underlying hash algorithm
    :<json string encrypted_key: U key encrypted with agents public key base64 encoded
    :<json string payload: (optional) payload encrypted with K key base64 encoded.

.. http:get::  /v2.1/keys/verify

    Get confirmation of bootstrap key derivation

    **Example request**:

    .. sourcecode::

        /v2.1/keys/verify?challenge=1234567890ABCDEFHIJ

    :param string challenge: 20 character random string with [a-Z,0-9] as symbols.

    **Example response:**

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "hmac": "719d992fb7d2a0761785fd023fe1cf8a584b835e465e71e2ef2632ff4e9938c080bdefba26194d8ea69dd7f9adee6c18"
          }
        }
    :>json string hmac: hmac with K key as key and the challenge

.. http:get::  /v2.1/quotes/integrity

    Get integrity quote from node

    **Example request**:

    .. sourcecode:: bash

      /v2.1/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x10401&partial=0

    :param string nonce: 20 character random string with [a-Z,0-9] as symbols.
    :param string mask: Mask for what PCRs from the TPM are included in the quote.
    :param string partial: Is either "0" or "1". If set to "1" the public key is excluded in the response.
    :param string ima_ml_entry: (optional) Line offset of the IMA entry list. If not present, 0 is assumed.

    **Example Response:**

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "quote": "r/1RDR4AYABYABPihP2yz+HcGF0vD0c4qiKt4nvSOAARURVNUAAAAAAAyQ9AAAAAAAAAAAAEgGRAjABY2NgAAAAEABAMAAAEAFCkk4YmhQECgWR+MnHqT9zftc3J8:ABQABAEAQ8IwX6Ak83zGhF6w8vOKOxsyTbxACQakYWGJaan3ewf+2O9TtiH5TLB1PXrPdhknsR/yx6OVUze9jTDvML9xkkK1ghXObCJ5gH+QX0udKfrLacm/iMds28SBtVO0rjqDIoYqGgXhH2ZhwGNDwjRCp6HquvtBe7pGEgtZlxf7Hr3wQRLO3FtliBPBR6gjOo7NC/uGsuPjdPU7c9ls29NgYSqdwShuNdRzwmZrF57umuUgF6GREFlxqLkGcbDIT1itV4zJZtI1caLVxqiH0Qv3sNqlNLsSHggkgc5S2EvNqwv/TsEZOq/leCoLtyVGYghPeGwg0RJfbe8cdyBWCQ6nOA==:AQAAAAQAAwAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAUABdJ/ntmsqy2aDi6NhKnLKz4k4uEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "hash_alg": "sha256",
            "enc_alg": "rsa",
            "sign_alg": "rsassa",
            "pubkey": "-----BEGIN PUBLIC KEY----- (...) -----END PUBLIC KEY-----\n"
            "boottime": 123456,
            "ima_measurement_list": "10 367a111b682553da5340f977001689db8366056a ima-ng sha256:94c0ac6d0ff747d8f1ca7fac89101a141f3e8f6a2c710717b477a026422766d6 boot_aggregate\n",
            "ima_measurement_list_entry": 0,
            "mb_measurement_list": "AAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACEAAABTcGVjIElEIEV2ZW50MDMAAAAAAAACAAIBAAAACwAgAAAAAAAACAAAAAEAAAALAJailtIk8oXGe [....]"
          }
        }

    :>json string quote: TPM integrity quote
    :>json string hash_alg: Used hash algorithm used in the quote (e.g. sha1, sha256, sha512).
    :>json string enc_alg: Encryption algorithm used in the quote (ecc, rsa).
    :>json string sign_alg: Signing algorthm used in the quote (rsassa, rsapss, ecdsa, ecdaa or ecschnorr).
    :>json string pubkey: PEM encoded public portion of the NK (digest is measured into PCR 16).
    :>json int boottime: Seconds since the system booted
    :>json string ima_measurement_list: (optional) IMA entry list. Is included if `IMA_PCR` (10) is included in the mask
    :>json int ima_measurement_list_entry: (optional) Starting line offset of the IMA entry list returned
    :>json string mb_measurement_list: (optional) UEFI Eventlog list base64 encoded. Is included if PCR 0 is included in the mask

    **Quote format**:
    The quote field contains the quote, the signature and the PCR values that make up the quote.

    .. sourcecode::

        QUOTE_DATA := rTPM_QUOTE:TPM_SIG:TPM_PCRS
        TPM_QUOTE  := base64(TPMS_ATTEST)
        TPM_SIG    := base64(TPMT_SIGNATURE)
        TPM_PCRS   := base64(tpm2_pcrs) // Can hold more that 8 PCR entries. This is a data structure generated by tpm2_quote


.. http:get::  /v2.1/quotes/identity

    Get identity quote from node

    **Example request:**

    .. sourcecode:: bash

      /v2.1/quotes/identity?nonce=1234567890ABCDEFHIJ

    :param string nonce: 20 character random string with [a-Z,0-9] as symbols.

    **Example response:**

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "quote": "r/1RDR4AYABYABPihP2yz+HcGF0vD0c4qiKt4nvSOAARURVNUAAAAAAAyQ9AAAAAAAAAAAAEgGRAjABY2NgAAAAEABAMAAAEAFCkk4YmhQECgWR+MnHqT9zftc3J8:ABQABAEAQ8IwX6Ak83zGhF6w8vOKOxsyTbxACQakYWGJaan3ewf+2O9TtiH5TLB1PXrPdhknsR/yx6OVUze9jTDvML9xkkK1ghXObCJ5gH+QX0udKfrLacm/iMds28SBtVO0rjqDIoYqGgXhH2ZhwGNDwjRCp6HquvtBe7pGEgtZlxf7Hr3wQRLO3FtliBPBR6gjOo7NC/uGsuPjdPU7c9ls29NgYSqdwShuNdRzwmZrF57umuUgF6GREFlxqLkGcbDIT1itV4zJZtI1caLVxqiH0Qv3sNqlNLsSHggkgc5S2EvNqwv/TsEZOq/leCoLtyVGYghPeGwg0RJfbe8cdyBWCQ6nOA==:AQAAAAQAAwAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAEAAAAUABdJ/ntmsqy2aDi6NhKnLKz4k4uEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "hash_alg": "sha256",
            "enc_alg": "rsa",
            "sign_alg": "rsassa",
            "pubkey": "-----BEGIN PUBLIC KEY----- (...) -----END PUBLIC KEY-----\n"
            "boottime": 123456
          }
        }

    :>json string quote: See `quotes/integrity`
    :>json string hash_alg: See `quotes/integrity`
    :>json string enc_alg: See `quotes/integrity`
    :>json string sign_alg: See `quotes/integrity`
    :>json string pubkey: See `quotes/integrity`
    :>json int boottime: See `quotes/integrity`

Cloud Registrar
~~~~~~~~~~~~~~~

.. http:get::  /v2.1/agents/

    Get ordered list of registered agents

    **Example response:**

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "uuids": [
              "5e600bce-a5cb-4f5a-bf08-46d0b45081c5",
              "6dab10e4-6619-4ff9-9062-ee6ad23ec24d",
              "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
            ]
          }
        }


.. http:get::  /v2.1/agents/{agent_id:UUID}

    Get EK certificate, AIK and optinal contact ip and port of agent `agent_id`.

    **Example response:**

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "aik_tpm": "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDjZ4J2HO7ekIONAX/eYIzt7ziiVAqE/1D7I9oEwIE88dIfqH0FQLJAg8u3+ZOgsJDQr9HiMhZRPhv8hRuia8ULdAomyOFA1cVzlBF+xcPUEemOIofbvcBNAoTY/x49r8LpqAEUBBiUeOniQbjfRaV2S5cEAA92wHLQAPLF9Sbf3zNxCnbhtRkEi6C3NYl8/FJqyu5Z9vvwEBBOFFTPasAxMtPm6a+Z5KJ4rDflipfaVcUvTKLIBRI7wkuXqhTR8BeIByK9upQ3iBo+FbYjWSf+BaN+wodMNgPbzxyL+tuxVqiPefBbv+sTWVxmYfo5i84FlbNOAW3APH8c+jZ3tgbt",
            "ek_tpm": "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAEMAEAgAAAAAAAEA0YwlPPIoXryMvbD5cIokN9OkljL2mV1oDxy7ETBXBe1nL9OWrLNO8Nbf8EaSNCtYCo5iqCwatnVRMPqNXcX8mQP0f/gDAqXryb+F192IJLKShHYSN32LJjCYOKrvNX1lrmr377juICFSRClE4q+pCfzhNj0Izw/eplaAI7gq41vrlnymWYGIEi4McErWG7qwr7LR9CXwiM7nhBYGtvobqoaOm4+f6zo3jQuks/KYjk0BR3mgAec/Qkfefw2lgSSYaPNl/8ytg6Dhla1LK8f7wWy/bv+3z7L11KLr8DZiFAzKBMiIDfaqNGYPhiFLKAMJ0MmJx63obCqx9z5BltV5YQ==",
            "ekcert": "MIIEGTCCAoGgAwIBAgIBBTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDEw1zd3RwbS1sb2NhbGNhMB4XDTIxMDQwOTEyNDAyNVoXDTMxMDQwNzEyNDAyNVowODE2MDQGA1UEAxMtZmVkb3JhMzM6NDdjYzJlMDMtNmRmMi00OGMyLWFmNGUtMDg1MWY1MWQyODJiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0YwlPPIoXryMvbD5cIokN9OkljL2mV1oDxy7ETBXBe1nL9OWrLNO8Nbf8EaSNCtYCo5iqCwatnVRMPqNXcX8mQP0f/gDAqXryb+F192IJLKShHYSN32LJjCYOKrvNX1lrmr377juICFSRClE4q+pCfzhNj0Izw/eplaAI7gq41vrlnymWYGIEi4McErWG7qwr7LR9CXwiM7nhBYGtvobqoaOm4+f6zo3jQuks/KYjk0BR3mgAec/Qkfefw2lgSSYaPNl/8ytg6Dhla1LK8f7wWy/bv+3z7L11KLr8DZiFAzKBMiIDfaqNGYPhiFLKAMJ0MmJx63obCqx9z5BltV5YQIDAQABo4HNMIHKMBAGA1UdJQQJMAcGBWeBBQgBMFIGA1UdEQEB/wRIMEakRDBCMRYwFAYFZ4EFAgEMC2lkOjAwMDAxMDE0MRAwDgYFZ4EFAgIMBXN3dHBtMRYwFAYFZ4EFAgMMC2lkOjIwMTkxMDIzMAwGA1UdEwEB/wQCMAAwIgYDVR0JBBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAKIwHwYDVR0jBBgwFoAUaO+9FEi5yX/GEnU+Vc6b3Si6JeAwDwYDVR0PAQH/BAUDAwcgADANBgkqhkiG9w0BAQsFAAOCAYEAaP/jI2i/hXDrthtaZypQ8VUG5AWFnMDtgiMhDSaKwOBfyxiUiYMTggGYXLOXGIu1SJGBtRJsh3QSYgs2tJCnntWF9Jcpmk6kIW/MC8shE+hdu/gQZKjAPZS4QCLIldv+GVZdNYEIv2FYDsKl6Bq1qUsYhAb7z29Nu1itpdvja2qy7ODJ0u+ThccBuH60VGFclFdJg19dvVQMnffxzjwxxJTMnVPmGoEdR94O0z7yxvqQ22+ITD9s1c3AfWcV+yLEpHqhXRqtKGdkAM5kU85kEs/ZPTLNutJHmF0/Vk9W2pRym8SrUe8G6mwxVW8lP9M7fhovKTzoXVFW3gQWQeUxhvWOncXxtARFLp/+f2mzGBRWxIslW17vpZ3QLlCdJ2C7P3U8x2tvkuyyDfz3/pq+8ECupZhdSvpHlBnWvqs1tAWKW0qI9d0xNYjj3Kfl3Lfy7kqqe6FIkvbDlVhw3vnJlclW+M6D86jBulL9ze+3zyMxy2z8m7UHiLCbamSe6m7W",
            "mtls_cert": "-----BEGIN CERTIFICATE----- (...) -----END CERTIFICATE-----",
            "ip": "127.0.0.1",
            "port": 9002,
            "regcount": 1
          }
        }

    :>json string aik_tpm: base64 encoded AIK. The AIK format is TPM2B_PUBLIC from tpm2-tss.
    :>json string ek_tpm: base64 encoded EK. When a `ekcert` is submitted it will be the public key of that certificate.
    :>json string ekcert: base64 encoded EK certificate. Should be in `DER` format. Gets extracted from NV `0x1c00002`.
    :>json string mtls_cert: Agent HTTPS server certificate. PEM encoded.
    :>json string ip: IPv4 address for contacting the agent. Might be `null`.
    :>json integer port: Port for contacting the agent. Might be `null`.


.. http:post::  /v2.1/agents/{agent_id:UUID}

    Add agent `agent_id` to registrar.

    **Example request**:

    .. sourcecode:: json

        {
          "ekcert": "MIIEGTCCAoGgAwIBAgIBBTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDEw1zd3RwbS1sb2NhbGNhMB4XDTIxMDQwOTEyNDAyNVoXDTMxMDQwNzEyNDAyNVowODE2MDQGA1UEAxMtZmVkb3JhMzM6NDdjYzJlMDMtNmRmMi00OGMyLWFmNGUtMDg1MWY1MWQyODJiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0YwlPPIoXryMvbD5cIokN9OkljL2mV1oDxy7ETBXBe1nL9OWrLNO8Nbf8EaSNCtYCo5iqCwatnVRMPqNXcX8mQP0f/gDAqXryb+F192IJLKShHYSN32LJjCYOKrvNX1lrmr377juICFSRClE4q+pCfzhNj0Izw/eplaAI7gq41vrlnymWYGIEi4McErWG7qwr7LR9CXwiM7nhBYGtvobqoaOm4+f6zo3jQuks/KYjk0BR3mgAec/Qkfefw2lgSSYaPNl/8ytg6Dhla1LK8f7wWy/bv+3z7L11KLr8DZiFAzKBMiIDfaqNGYPhiFLKAMJ0MmJx63obCqx9z5BltV5YQIDAQABo4HNMIHKMBAGA1UdJQQJMAcGBWeBBQgBMFIGA1UdEQEB/wRIMEakRDBCMRYwFAYFZ4EFAgEMC2lkOjAwMDAxMDE0MRAwDgYFZ4EFAgIMBXN3dHBtMRYwFAYFZ4EFAgMMC2lkOjIwMTkxMDIzMAwGA1UdEwEB/wQCMAAwIgYDVR0JBBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAKIwHwYDVR0jBBgwFoAUaO+9FEi5yX/GEnU+Vc6b3Si6JeAwDwYDVR0PAQH/BAUDAwcgADANBgkqhkiG9w0BAQsFAAOCAYEAaP/jI2i/hXDrthtaZypQ8VUG5AWFnMDtgiMhDSaKwOBfyxiUiYMTggGYXLOXGIu1SJGBtRJsh3QSYgs2tJCnntWF9Jcpmk6kIW/MC8shE+hdu/gQZKjAPZS4QCLIldv+GVZdNYEIv2FYDsKl6Bq1qUsYhAb7z29Nu1itpdvja2qy7ODJ0u+ThccBuH60VGFclFdJg19dvVQMnffxzjwxxJTMnVPmGoEdR94O0z7yxvqQ22+ITD9s1c3AfWcV+yLEpHqhXRqtKGdkAM5kU85kEs/ZPTLNutJHmF0/Vk9W2pRym8SrUe8G6mwxVW8lP9M7fhovKTzoXVFW3gQWQeUxhvWOncXxtARFLp/+f2mzGBRWxIslW17vpZ3QLlCdJ2C7P3U8x2tvkuyyDfz3/pq+8ECupZhdSvpHlBnWvqs1tAWKW0qI9d0xNYjj3Kfl3Lfy7kqqe6FIkvbDlVhw3vnJlclW+M6D86jBulL9ze+3zyMxy2z8m7UHiLCbamSe6m7W",
          "aik_tpm": "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQCg5mMzNFqdlUbW8uI/GuMcIIvOXXTohHFTas59JlwrJQVed+5klWP+j7tI7492YPmCnoZvP4T4YdT1PN7tHHGfF81AeMnuw5GV5RkW/QeSD+ssB4f6AfuzYJgBkc28zKmpRRHUbwN4rb/HnJgRXdXsuIcnOqGcC39pD0kiu5TrN6hekjxTQtfAbIlQwwDwHCxKWdtH5x7avd15hqc6cBc2gjTQksXrk+OiMwOFTJ68n0qY+dQYuBTjE66YXn9S8cdU9sbjCTSdLRqFEpAyfkSV8F2An7N3DWNIA+PW/mVmd8XhPeYUoMlweXBOwc3e9zM9lZmMvregrFHKYc7CXChz",
          "mtls_cert": "-----BEGIN CERTIFICATE----- (...) -----END CERTIFICATE-----",
          "ip": "127.0.0.1",
          "port": "9002"
        }


    :<json string ekcert: base64 encoded EK certificate. Should be in `DER` format. Gets extracted from NV `0x1c00002`.
    :<json string aik_tpm: base64 encoded AIK. The AIK format is TPM2B_PUBLIC from tpm2-tss.
    :<json string mtls_cert: Agent HTTPS server certificate. PEM encoded.
    :<json string ip: (Optional) contact IPv4 address for the verifier and tenant to use.
    :<json string port: (Optional) contact port for the verifier and tenant to use.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "blob": "utzA3gAAAAEARAAgC/w9LP1PKZ9thEk+GkMg4m+tkc9TkavcvFiFL6xbXM2q2fTRyKmQnxuCJc0tQdgsRXMftGiKJyA/SUo8kGNVmcNfAQCs79kl9Ir49JJ8rfyMfDIqOuSVlu9PhxGUOeVzAdxyUmPxq5Qp0s431n/KeL/5nUaVXC+qpOftF4bmVtXwLGTTUbKtyT3GG+9ujkjiwHCQhSKTQ8HiuARgXXh13ntFsJ75PBD5dWauLTuciYZI/WQDVXAcgMnQNxodJUi9ir1GxJWz8zufjVQTVjrlgsgeBdOKbB6+H81K1d9prWhZaVLP+wIwO3YuWgtNHNi90E1z/dah2pzfUpLvJo3lNZ4bJgrJUR507AokGKIFm7EfOf+5WWWAvGxGtgqTJB27vgE0CVBLEuDUHoRcLVBi1Np4GGNTByalxbulg8x1eGtZyuQF"
          }
        }

    :>json string blob: base64 encoded blob containing the `aik_tpm` name and a challenge. Is encrypted with `ek_tpm`.


.. http:delete::  /v2.1/agents/{agent_id:UUID}

    Remove agent `agent_id` from registrar.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {}
        }


.. http:put::  /v2.1/agents/{agent_id:UUID}/activate

    Activate physical agent `agent_id`

    **Example request:**

    .. sourcecode:: json

        {
          "auth_tag": "7087ba88746886262de743587ed97aea6b6e3f32755de5d85415c40feef3169bc58d38855ddb96e32efdd8745d0bdfef"
        }


    :<json string auth_tag: hmac containing the challenge from `blob` and the `agent_id`.

.. http:put::  /v2.1/agents/{agent_id:UUID}/vactivate

    Activate virtual (vTPM) agent `agent_id`

    **Requires JSON Body**:

    .. sourcecode:: js

        {
          "deepquote" : b64,
        }


Changelog
---------
Changes between the different API versions.

Changes from v2.0 to v2.1
~~~~~~~~~~~~~~~~~~~~~~~~~
API version 2.1 was first implemented in Keylime 6.4.0.

 * Added `ak_tpm` field to `POST /v2.1/agents/{agent_id:UUID}` in cloud verifier.
 * Added `mtls_cert` field to `POST /v2.1/agents/{agent_id:UUID}` in cloud verifier.
 * Removed `vmask` parameter from

This removed the requirement for the verifier to connect to the registrar.

Changes from v1.0 to v2.0
~~~~~~~~~~~~~~~~~~~~~~~~~
API version 2.0 was first implemented in Keylime 6.3.0.

 * Added mTLS authentication to agent endpoints.
 * Added `supported_version` field to `POST /v2.0/agents/{agent_id:UUID}` in cloud verifier.
 * Added `mtls_cert` field to `POST/GET /v2.0/agents/{agent_id:UUID}` in registrar.
 * Added `/version` endpoint to agent. Note that this endpoint is not implemented by all agents.
 * Dropped zlib encryption for `quote` field data in `GET /v2.0/quotes/integrity`/`GET /v2.0/quotes/identity`.
