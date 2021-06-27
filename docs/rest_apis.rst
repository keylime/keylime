==========
Rest API's
==========
All Keylime APIs use `REST (Representational State Transfer)`.

Authentication and authorization
--------------------------------

Not yet implemented

RESTful API for Keylime (v1.0)
----------------------------
Keylime API is versioned. More information can be found here: https://github.com/keylime/enhancements/blob/master/45_api_versioning.md

Note: Versions before 6.2.0 used `v2` as a prefix.

General responses
~~~~~~~~~~~~~~~~~~~

.. http:any:: /

    Generic fields in responses

    :>json int code: HTTP status code
    :>json string status: textual context of that status
    :>json object results: Holds the actual data.


Cloud verifier (CV)
~~~~~~~~~~~~~~~~~~~

.. http:get::  /v1.0/agents/{agent_id:UUID}

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
            "allowlist_len": 0,
            "mb_refstate_len": 0,
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
            "sign_alg": "rsassa"
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
    :>json int mb_refstate_len: Length of the measured boot reference state policy.
    :>json list[string] accept_tpm_hash_algs: Accepted TPM hashing algorithms. sha1 must be enabled for IMA validation to work.
    :>json list[string] accept_tpm_encryption_algs: Accepted TPM encryption algorithms.
    :>json list[string] accept_tpm_signing_algs: Accepted TPM signing algorithms.
    :>json string hash_alg: Used hashing algorithm.
    :>json string enc_alg: Used encryption algorithm.
    :>json string sign_alg: Used signing algorithm.



.. http:post::  /v1.0/agents/{agent_id:UUID}

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
          ]
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

.. http:delete::  /v1.0/agents/{agent_id:UUID}

    Terminate instance `agent_id`.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {}
        }


.. http:put::  /v1.0/agents/{agent_id:UUID}/reactivate

    Start agent `agent_id` (for an already bootstrapped `agent_id` node)

.. http:put::  /v1.0/agents/{agent_id:UUID}/stop

    Stop cv polling on `agent_id`, but don’t delete (for an already started `agent_id`).
    This will make the agent verification fail.

Cloud Agent
~~~~~~~~~~~

.. http:get::  /v1.0/keys/pubkey

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


.. http:post::  /v1.0/keys/vkey

    Send `v_key` to node.

    **Example request**:

    .. sourcecode:: json

      {
        "encrypted_key": "MN/F33jjuLiIuRH8fF7pMtw6Hoe2KG10zg+/xuuZLa5d1WB2aR6feVCwknZDe/dhG51yB0tKau8fCNUz8KMxyWoFkalIY4vVG6DNpLouDjb+vMvI6RmVmCBwO5zx6R802wK2z2yUbcn11TU/k2zHq34CNFIgI5pQu7cnLMzCLW6NLEp8N0IOQL6D+uV9emkheJH1g40xYwUaKoABWjZeaJN5dvKwbkpIf2m+CROmCNPCidh87J0g7BENUvlSUO1FPfRjch4kyxLrp+aMu9zmzF/tZErh1zk+nUamtrgl25pEImw+Cn9RIVTd6fBkmzlGzch5foAqZCyZ0AhQ0ONuWw==",
      }

    :<json string encrypted_key: V key encrypted with agents public key base64 encoded.

.. http:post::  /v1.0/keys/ukey

    Send `u_key` to node (with optional payload)

    **Example request**:

    .. sourcecode:: json

      {
        "auth_tag" : "3876c08b30c16c4140ee04300bb4262bbcc9034d8a2ed8c90784f13b484a570bf9da3d5c372141bd16d85de05c4c7cce",
        "encrypted_key": "iAckMZgZc8r43pF0iW8iwwAorD+rvnvF7AShhlz6+am+ryqW+907UynOrWrIrAseyVRE7ouHpr547gnwfF7oKeBFlEdWnE6FbQl9o6tk86BzQy3PImBLxJD/y/MmSuNR5pGQwZCueKI0ji3Nqq6heOgSvnMRC0PHgyumOsYiAnbDNyryvfwO4HsqdqMcEsBu1IVzU3EtJWhfQ8i/UpvHy6Jq4bBh+mw5HZwmK93bmsLXNKgjPWAicsCZINUAPVMCUL7dcDd4zijsBxMxiZF7Js7V25wKKFer2zqKsE5omLy9sKotFfWjgaROPLrKXxuDgNmlONJnD0btLZBa9T+mmA==",
        "payload": "WcXpUr4G9yfvVaojNx6K2XZuDYRkFoZQhHrvZB+TKZqsq41g"
      }

    :<json string auth_tag: hmac with K key as key and UUID
    :<json string encrypted_key: U key encrypted with agents public key base64 encoded
    :<json string payload: (optional) payload encrypted with K key base64 encoded.

.. http:get::  /v1.0/keys/verify

    Get confirmation of bootstrap key derivation

    **Example request**:

    .. sourcecode::

        /v1.0/keys/verify?challenge=1234567890ABCDEFHIJ

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

.. http:get::  /v1.0/quotes/integrity

    Get integrity quote from node

    **Example request**:

    .. sourcecode:: bash

      /v1.0/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&vmask=0x808000&partial=0

    :param string nonce: 20 character random string with [a-Z,0-9] as symbols.
    :param string mask: Mask for what PCRs from the TPM are included in the quote.
    :param string vmask: Mask for what PCRs from the TPM are included in the quote.
    :param string partial: Is either "0" or "1". If set to "1" the public key is excluded in the response.

    **Example Response:**

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "quote": "reJz7H+Ls3iDBoMTAveopx4nFmZcuNzl+8C17UXNQVTE8ol0hPas1zoz9rfWtUAZhQyNjE1MzcwtLA0cnZxdXNw9PLwYg4K79OgdISYLYjAqSAsoMYmZmIDYDNzNDgyODwvGrx568qv6t6FEf8yvfOm1lzW7mayGazWW6GsKNVR9NWgBRxysC:eJwBBgH5/gAUAAsBADN1NUAMPxXX1HCwiSSHtuaHiFjHNlv+rGzEK1wNhlNWtmuiPWy5eC3dN5Axyaq9T+lznKTnOSfa0PLH0Wgu33qCcRavdGv8TIGxV/FwwlYyQGhbrm5gA+HQr1QlQ+UbvQcR97CNCCXsaMlXQJEqf/imlF46v9TS1KHhSMxgwE2dEeanXmutJEMJQizwqb4bANMpeiO6Rds3OxPxSuLJkhJM6RZg9coPCZaqWhxUuGf2uk8FYcFKmTUvID/eKPvX0DfJZ9K0czEj3gp2keLlLYD48vJVkklAtM91Tv+NFTcOzUq7iD1qoeFLKEgzdQVUWluMJU/HlkG0yjcOQtL80hV4OX0R:eJxjZGBg4GZgZmhwZBgwwAjEzECsQLFJCgx5yva31pyQ9Xx9O6uQ8aEy086yhXvK1+edqF2eqnFQgucGYRP+EwAUO3IUEAkA44Iwlw==",
            "hash_alg": "sha256",
            "enc_alg": "rsa",
            "sign_alg": "rsassa",
            "pubkey": "-----BEGIN PUBLIC KEY----- (...) -----END PUBLIC KEY-----\n"
          }
        }

    :>json string quote: TPM integrity quote
    :>json string ima_measurement_list: (optional) IMA entry list base64 encoded. Is included if `IMA_PCR` (10) is included in the mask
    :>json string ima_measurement_list: (optional) UEFI Eventlog list base64 encoded. Is included if PCR 0 is included in the mask


.. http:get::  /v1.0/quotes/identity

    Get identity quote from node

    **Example request:**

    .. sourcecode:: bash

      /v1.0/quotes/identity?nonce=1234567890ABCDEFHIJ

    :param string nonce: 20 character random string with [a-Z,0-9] as symbols.

    **Example response:**

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "quote": "reJz7H+Ls3iDBoMTAveopx4nFmZcuNzl+8C17UXNQVTE8ol0hPas1zoz9rfWtUAZhQyNjE1MzcwtLA0cnZxdXNw9PLwYg4G6yVgFSkiA2o4KkgDKDmJkZiM3AzcwIJBUyjaoZjbxVfS+b2fyWP7T5ZcUjvZsSJUdvMG9u0PO/5nofAKALJ+E=:eJwBBgH5/gAUAAsBAD0E2jhLKUswajxY96mZ6N9IrxXhIDuA+dNFUouqjKcfoIcyNke8kbG2YDWK1alkExGGnCehkq213QSKFzK2Qto5SgKDtVkIuvvDW2vvYeMph6YwyBGq0V4s9rtORfyzDXZyGvdY/fmPsALQNCdtyDySFKZA8KVbcaTRXQtqrXe4fNjNLT0mxO0z8lbiWrsQcC2HAmsUFTpkgjKlaAW3lgzh0pfSvtl/QMNmXmIvB/1zWhP4HgMpexvHTgAZXVayZEOiRmtfdvoNoAYaoGUKXxgJKHZzm2moxriJLsV2r0B0z3yc+v4gkeXIGcSIMhgL85n/+0JWeTFFSPp+dTMh/m26l3gu:eJxjZGBg4GZgZmRgZBgwALKaCYgVGBpKbF6fSV0gtmUO646O/9s7Nj2O1pA68Wj3TBfthiuqQbsJmaTAkKdsf2vNCVnP17ezChkfKjPtLFu4p3x93ona5akaByV4btDeN6OAWgAAgXUg0Q==",
            "hash_alg": "sha256",
            "enc_alg": "rsa",
            "sign_alg": "rsassa",
            "pubkey": "-----BEGIN PUBLIC KEY----- (...) -----END PUBLIC KEY-----\n"
          }
        }

    :>json string quoute: Identity quote from the TPM



Cloud Registrar
~~~~~~~~~~~~~~~

.. http:get::  /v1.0/agents/

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


.. http:get::  /v1.0/agents/{agent_id:UUID}

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
            "ip": "127.0.0.1",
            "port": 9002,
            "regcount": 1
          }
        }

    :>json string aik_tpm: base64 encoded AIK. The AIK format is TPM2B_PUBLIC from tpm2-tss.
    :>json string ek_tpm: base64 encoded EK. When a `ekcert` is submitted it will be the public key of that certificate.
    :>json string ekcert: base64 encoded EK certificate. Should be in `DER` format. Gets extracted from NV `0x1c00002`.
    :>json string ip: IPv4 address for contacting the agent. Might be `null`.
    :>json integer port: Port for contacting the agent. Might be `null`.


.. http:post::  /v1.0/agents/{agent_id:UUID}

    Add agent `agent_id` to registrar.

    **Example request**:

    .. sourcecode:: json

        {
          "ekcert": "MIIEGTCCAoGgAwIBAgIBBTANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDEw1zd3RwbS1sb2NhbGNhMB4XDTIxMDQwOTEyNDAyNVoXDTMxMDQwNzEyNDAyNVowODE2MDQGA1UEAxMtZmVkb3JhMzM6NDdjYzJlMDMtNmRmMi00OGMyLWFmNGUtMDg1MWY1MWQyODJiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0YwlPPIoXryMvbD5cIokN9OkljL2mV1oDxy7ETBXBe1nL9OWrLNO8Nbf8EaSNCtYCo5iqCwatnVRMPqNXcX8mQP0f/gDAqXryb+F192IJLKShHYSN32LJjCYOKrvNX1lrmr377juICFSRClE4q+pCfzhNj0Izw/eplaAI7gq41vrlnymWYGIEi4McErWG7qwr7LR9CXwiM7nhBYGtvobqoaOm4+f6zo3jQuks/KYjk0BR3mgAec/Qkfefw2lgSSYaPNl/8ytg6Dhla1LK8f7wWy/bv+3z7L11KLr8DZiFAzKBMiIDfaqNGYPhiFLKAMJ0MmJx63obCqx9z5BltV5YQIDAQABo4HNMIHKMBAGA1UdJQQJMAcGBWeBBQgBMFIGA1UdEQEB/wRIMEakRDBCMRYwFAYFZ4EFAgEMC2lkOjAwMDAxMDE0MRAwDgYFZ4EFAgIMBXN3dHBtMRYwFAYFZ4EFAgMMC2lkOjIwMTkxMDIzMAwGA1UdEwEB/wQCMAAwIgYDVR0JBBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAKIwHwYDVR0jBBgwFoAUaO+9FEi5yX/GEnU+Vc6b3Si6JeAwDwYDVR0PAQH/BAUDAwcgADANBgkqhkiG9w0BAQsFAAOCAYEAaP/jI2i/hXDrthtaZypQ8VUG5AWFnMDtgiMhDSaKwOBfyxiUiYMTggGYXLOXGIu1SJGBtRJsh3QSYgs2tJCnntWF9Jcpmk6kIW/MC8shE+hdu/gQZKjAPZS4QCLIldv+GVZdNYEIv2FYDsKl6Bq1qUsYhAb7z29Nu1itpdvja2qy7ODJ0u+ThccBuH60VGFclFdJg19dvVQMnffxzjwxxJTMnVPmGoEdR94O0z7yxvqQ22+ITD9s1c3AfWcV+yLEpHqhXRqtKGdkAM5kU85kEs/ZPTLNutJHmF0/Vk9W2pRym8SrUe8G6mwxVW8lP9M7fhovKTzoXVFW3gQWQeUxhvWOncXxtARFLp/+f2mzGBRWxIslW17vpZ3QLlCdJ2C7P3U8x2tvkuyyDfz3/pq+8ECupZhdSvpHlBnWvqs1tAWKW0qI9d0xNYjj3Kfl3Lfy7kqqe6FIkvbDlVhw3vnJlclW+M6D86jBulL9ze+3zyMxy2z8m7UHiLCbamSe6m7W",
          "aik_tpm": "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQCg5mMzNFqdlUbW8uI/GuMcIIvOXXTohHFTas59JlwrJQVed+5klWP+j7tI7492YPmCnoZvP4T4YdT1PN7tHHGfF81AeMnuw5GV5RkW/QeSD+ssB4f6AfuzYJgBkc28zKmpRRHUbwN4rb/HnJgRXdXsuIcnOqGcC39pD0kiu5TrN6hekjxTQtfAbIlQwwDwHCxKWdtH5x7avd15hqc6cBc2gjTQksXrk+OiMwOFTJ68n0qY+dQYuBTjE66YXn9S8cdU9sbjCTSdLRqFEpAyfkSV8F2An7N3DWNIA+PW/mVmd8XhPeYUoMlweXBOwc3e9zM9lZmMvregrFHKYc7CXChz",
          "ip": "127.0.0.1",
          "port": "9002"
        }


    :<json string ekcert: base64 encoded EK certificate. Should be in `DER` format. Gets extracted from NV `0x1c00002`.
    :<json string aik_tpm: base64 encoded AIK. The AIK format is TPM2B_PUBLIC from tpm2-tss.
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


.. http:delete::  /v1.0/agents/{agent_id:UUID}

    Remove agent `agent_id` from registrar.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {}
        }


.. http:put::  /v1.0/agents/{agent_id:UUID}/activate

    Activate physical agent `agent_id`

    **Example request:**

    .. sourcecode:: json

        {
          "auth_tag": "7087ba88746886262de743587ed97aea6b6e3f32755de5d85415c40feef3169bc58d38855ddb96e32efdd8745d0bdfef"
        }


    :<json string auth_tag: hmac containing the challenge from `blob` and the `agent_id`.

.. http:put::  /v1.0/agents/{agent_id:UUID}/vactivate

    Activate virtual (vTPM) agent `agent_id`

    **Requires JSON Body**:

    .. sourcecode:: js

        {
          "deepquote" : b64,
        }

Tenant WebApp
~~~~~~~~~~~~~

.. http:get::  /v1.0/agents/

    Get ordered list of registered agents

.. http:get::  /v1.0/agents/{agent_id:UUID}

    Get list of registered agents

.. http:put::  /v1.0/agents/{agent_id:UUID}

    Start agent `agent_id` (For an already bootstrapped `agent_id` agent)

.. http:post::  /v1.0/agents/{agent_id:UUID}

    Add agent `agent_id` to registrar

    **Requires JSON Body**:

    .. sourcecode:: json

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

.. http:get::  /v1.0/logs/

          Get terminal log data

.. http:get::  /v1.0/logs/{logType:string}

          Get terminal log data for given logType

          Optional query parameters:

          .. sourcecode:: bash

            pos : int, (opt)

          Example:

          .. sourcecode:: bash

            /v1.0/logs/tenant?pos=#
