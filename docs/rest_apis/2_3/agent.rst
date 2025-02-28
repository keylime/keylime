Agent
~~~~~

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

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
    :>json string supported_version: The latest version the agent supports.

.. http:get::  /v2.3/agent/info

    Retrieves information about an agent

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "agent_uuid": "e1ef9f28-be55-47b0-a6c1-8bef90294b93",
            "tpm_hash_alg": "sha256",
            "tpm_enc_alg": "rsa",
            "tpm_sign_alg": "rsassa",
            "ak_handle": "1078035599"
          }
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
    :>json string agent_uuid: The UUID of the agent.
    :>json string tpm_hash_alg: The hashing algorithm used by this agent's TPM device.
    :>json string tpm_enc_alg: The encryption algorithm used by this agent's TPM device.
    :>json string tpm_sign_alg: The signing algorithm used by this agent's TPM device.
    :>json string ak: The Attestation Key handle of the TPM device used by this agent.

.. http:get::  /v2.3/keys/pubkey

    Retrieves the agent's public key.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "pubkey": "-----BEGIN PUBLIC KEY----- (...) -----END PUBLIC KEY-----\n"
          }
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
    :>json string pubkey: Public rsa key of the agent used for encrypting V and U key.

.. http:post::  /v2.3/keys/vkey

    Send `v_key` to node.

    **Example request**:

    .. sourcecode:: json

      {
        "encrypted_key": "MN/F33jjuLiIuRH8fF7pMtw6Hoe2KG10zg+/xuuZLa5d1WB2aR6feVCwknZDe/dhG51yB0tKau8fCNUz8KMxyWoFkalIY4vVG6DNpLouDjb+vMvI6RmVmCBwO5zx6R802wK2z2yUbcn11TU/k2zHq34CNFIgI5pQu7cnLMzCLW6NLEp8N0IOQL6D+uV9emkheJH1g40xYwUaKoABWjZeaJN5dvKwbkpIf2m+CROmCNPCidh87J0g7BENUvlSUO1FPfRjch4kyxLrp+aMu9zmzF/tZErh1zk+nUamtrgl25pEImw+Cn9RIVTd6fBkmzlGzch5foAqZCyZ0AhQ0ONuWw=="
      }

    :<json string encrypted_key: V key encrypted with the agent's public key base64 encoded.


    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {}
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object (empty)


.. http:post::  /v2.3/keys/ukey

    Send `u_key` to node (with optional payload)

    **Example request**:

    .. sourcecode:: json

      {
        "auth_tag" : "3876c08b30c16c4140ee04300bb4262bbcc9034d8a2ed8c90784f13b484a570bf9da3d5c372141bd16d85de05c4c7cce",
        "encrypted_key": "iAckMZgZc8r43pF0iW8iwwAorD+rvnvF7AShhlz6+am+ryqW+907UynOrWrIrAseyVRE7ouHpr547gnwfF7oKeBFlEdWnE6FbQl9o6tk86BzQy3PImBLxJD/y/MmSuNR5pGQwZCueKI0ji3Nqq6heOgSvnMRC0PHgyumOsYiAnbDNyryvfwO4HsqdqMcEsBu1IVzU3EtJWhfQ8i/UpvHy6Jq4bBh+mw5HZwmK93bmsLXNKgjPWAicsCZINUAPVMCUL7dcDd4zijsBxMxiZF7Js7V25wKKFer2zqKsE5omLy9sKotFfWjgaROPLrKXxuDgNmlONJnD0btLZBa9T+mmA==",
        "payload": "WcXpUr4G9yfvVaojNx6K2XZuDYRkFoZQhHrvZB+TKZqsq41g"
      }

    :<json string auth_tag: HMAC calculated with K key as key and UUID as data, using SHA-384 as the underlying hash algorithm
    :<json string encrypted_key: U key encrypted with the agent's public key base64 encoded
    :<json string payload: (optional) payload encrypted with K key base64 encoded.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {}
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object (empty)


.. http:get::  /v2.3/keys/verify

    Get confirmation of bootstrap key derivation

    **Example request**:

    .. sourcecode:: http

       GET /v2.2/keys/verify?challenge=1234567890ABCDEFHIJK HTTP/1.1
       Host: example.com
       Accept: application/json

    :query challenge: 20 character random string with [a-Z,0-9] as symbols.


    **Example response:**

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "hmac": "719d992fb7d2a0761785fd023fe1cf8a584b835e465e71e2ef2632ff4e9938c080bdefba26194d8ea69dd7f9adee6c18"
          }
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
    :>json string hmac: hmac with K key as key and the challenge

.. http:get::  /v2.3/quotes/integrity

    Get integrity quote from node

    **Example request**:

    .. sourcecode:: http

       GET /v2.2/quotes/integrity?nonce=1234567890ABCDEFHIJK&mask=0x10401&partial=0 HTTP/1.1
       Host: example.com
       Accept: application/json

    :query nonce: 20 character random string with [a-Z,0-9] as symbols.
    :query mask: Mask for what PCRs from the TPM are included in the quote.
    :query partial: Is either "0" or "1". If set to "1" the public key is excluded in the response.
    :query ima_ml_entry: (optional) Line offset of the IMA entry list. If not present, 0 is assumed.


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

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
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


.. http:get::  /v2.3/quotes/identity

    Get identity quote from node

    **Example request:**

    .. sourcecode:: http

       GET /v2.1/quotes/identity?nonce=1234567890ABCDEFHIJK HTTP/1.1
       Host: example.com
       Accept: application/json

    :query nonce: 20 character random string with [a-Z,0-9] as symbols.


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

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
    :>json string quote: See `quotes/integrity`
    :>json string hash_alg: See `quotes/integrity`
    :>json string enc_alg: See `quotes/integrity`
    :>json string sign_alg: See `quotes/integrity`
    :>json string pubkey: See `quotes/integrity`
    :>json int boottime: See `quotes/integrity`

