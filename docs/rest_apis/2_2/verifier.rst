Verifier
~~~~~~~~

.. http:get::  /v2.2/agents/{agent_id:UUID}

    Get status of agent `agent_id` from Verifier

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
            "has_runtime_policy": 0,
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
            "last_event_id": "qoute_validation.quote_validation",
            "attestation_count": 240,
            "last_received_quote": 1676644582,
            "last_successful_attestation": 1676644462
          }
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
    :>json int operational_state: Current state of the agent in the CV. Defined in https://github.com/keylime/keylime/blob/master/keylime/common/states.py
    :>json string v: V key for payload base64 encoded or null. Decoded length is 32 bytes
    :>json string ip: Agents contact ip address for the CV
    :>json string port: Agents contact port for the CV
    :>json string tpm_policy: Static PCR policy and mask for TPM
    :>json string vtpm_policy: Static PCR policy and mask for vTPM
    :>json string meta_data: Metadata about the agent. Normally contains certificate information if a CA is used.
    :>json int has_mb_refstate: 1 if a measured boot refstate was provided via tenant, 0 otherwise.
    :>json int has_runtime_policy: 1 if a runtime policy (allowlist and excludelist) was provided via tenant, 0 otherwise.
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
    :>json int attestation_count: Number of quotes received from the agent which have verified successfully.
    :>json int last_received_quote: Timestamp of the last quote received from the agent irrespective of validity. A value of 0 indicates no quotes have been received. May be `null` after upgrading from a previous Keylime version.
    :>json int last_successful_attestation: Timestamp of the last quote received from the agent which verified successfully. A value of 0 indicates no valid quotes have been received. May be `null` after upgrading from a previous Keylime version.


.. http:post::  /v2.2/agents/{agent_id:UUID}

    Add new agent `instance_id` to Verifier.

    **Example request**:

    .. sourcecode:: json

        {
          "v": "3HZMmIEc6yyjfoxdCwcOgPk/6X1GuNG+tlCmNgqBM/I=",
          "cloudagent_ip": "127.0.0.1",
          "cloudagent_port": 9002,
          "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
          "ak_tpm": "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDjZ4J2HO7ekIONAX/eYIzt7ziiVAqE/1D7I9oEwIE88dIfqH0FQLJAg8u3+ZOgsJDQr9HiMhZRPhv8hRuia8ULdAomyOFA1cVzlBF+xcPUEemOIofbvcBNAoTY/x49r8LpqAEUBBiUeOniQbjfRaV2S5cEAA92wHLQAPLF9Sbf3zNxCnbhtRkEi6C3NYl8/FJqyu5Z9vvwEBBOFFTPasAxMtPm6a+Z5KJ4rDflipfaVcUvTKLIBRI7wkuXqhTR8BeIByK9upQ3iBo+FbYjWSf+BaN+wodMNgPbzxyL+tuxVqiPefBbv+sTWVxmYfo5i84FlbNOAW3APH8c+jZ3tgbt",
          "mtls_cert": "-----BEGIN CERTIFICATE----- (...) -----END CERTIFICATE-----",
          "runtime_policy_name": null,
          "runtime_policy": "",
          "runtime_policy_sig": "",
          "runtime_policy_key": "",
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

    :<json string v: (Optional) V key for payload base64 encoded. Decoded length is 32 bytes.
    :<json string cloudagent_ip: Agents contact ip address for the CV.
    :<json string cloudagent_port: Agents contact port for the CV.
    :<json string tpm_policy: Static PCR policy and mask for TPM. Is a string encoded dictionary that also includes a `mask` for which PCRs should be included in a quote.
    :<json string ak_tpm: AK of the agent, base64-encoded, same as `aik_tpm` in the registrar.
    :<json string mtls_cert: MTLS certificate of the agent, PEM encoded, same as in the registrar.
    :<json string runtime_policy_name: Optional. If specified with a `runtime_policy` it is saved under that name, if specified without, then the policy with that name is loaded.
    :<json string runtime_policy: Runtime policy JSON object, base64 encoded.
    :<json string runtime_policy_sig: Optional runtime policy detached signature, base64-encoded. Must also provide `runtime_policy_key`.
    :<json string runtime_policy_key: Optional runtime policy detached signature key, base64-encoded. Must also provide `runtime_policy_sig`.
    :<json string mb_refstate: Measured boot reference state policy.
    :<json string ima_sign_verification_keys: IMA signature verification public keyring JSON object string encoded.
    :<json string metadata: Metadata about the agent. Contains `cert_serial` and `subject` if a CA is used with the tenant.
    :<json string revocation_key: Key which is used to sign the revocation message of the agent.
    :<json list[string] accept_tpm_hash_algs: Accepted TPM hashing algorithms. sha1 must be enabled for IMA validation to work.
    :<json list[string] accept_tpm_encryption_algs: Accepted TPM encryption algorithms.
    :<json list[string] accept_tpm_signing_algs: Accepted TPM signing algorithms.
    :<json string supported_version: supported API version of the agent. `v` prefix must not be included.


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


.. http:delete::  /v2.2/agents/{agent_id:UUID}

    Terminate instance `agent_id`.

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


.. http:put::  /v2.2/agents/{agent_id:UUID}/reactivate

    Start agent `agent_id` (for an already bootstrapped `agent_id` node)

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


.. http:put::  /v2.2/agents/{agent_id:UUID}/stop

    Stop Verifier polling on `agent_id`, but don’t delete (for an already started `agent_id`).
    This will make the agent verification fail.

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


.. http:post::  /v2.2/allowlists/{runtime_policy_name:string}

    Add new named IMA policy `runtime_policy_name` to Verifier.

    **Example request**:

    .. sourcecode:: json

        {
          "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
          "runtime_policy": "",
          "runtime_policy_sig": "",
          "runtime_policy_key": ""
        }

    :<json string tpm_policy: Static PCR policy and mask for TPM. Is a string encoded dictionary that also includes a `mask` for which PCRs should be included in a quote.
    :<json string runtime_policy: Runtime policy JSON object, base64 encoded.
    :<json string runtime_policy_sig: Optional runtime policy detached signature, base64-encoded. Must also provide `runtime_policy_key`.
    :<json string runtime_policy_key: Optional runtime policy detached signature key, base64-encoded. Must also provide `runtime_policy_sig`.


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


.. http:get::  /v2.2/allowlists/[runtime_policy_name:string]

    If `runtime_policy_name` is provided, get the named runtime policies from the Verifier.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "name": "",
            "tpm_policy": "{\"22\": [\"0000000000000000000000000000000000000001\", \"0000000000000000000000000000000000000000000000000000000000000001\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001\", \"ffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\", \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"], \"15\": [\"0000000000000000000000000000000000000000\", \"0000000000000000000000000000000000000000000000000000000000000000\", \"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"], \"mask\": \"0x408000\"}",
            "runtime_policy": ""
          }
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json string name: Name of the requested IMA policy.
    :>json string tpm_policy: Static PCR policy and mask for TPM. Is a string encoded dictionary that also includes a `mask` for which PCRs should be included in a quote.
    :>json string runtime_policy: Runtime policy JSON object, base64 encoded.


    Otherwise, retrieve list of names of the runtime policies.

    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "runtimepolicy names": [
                "runtimepolicyname1", 
                "runtimepolicyname2"
            ],
          }
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
    :>json list[string] runtimepolicy names: List of names of the runtime policies.


.. http:delete::  /v2.2/allowlist/{runtime_policy_name:string}

    Delete IMA policy `runtime_policy_name`.

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

.. http:get::  /v2.2/verify/identity

    Verify the identity of a node monitored by keylime

    **Example request**:

    .. sourcecode:: http

       GET /v2.2/verify/identity?agent_uuid=e1ef9f28-be55-47b0-a6c1-8bef90294b93&hash_alg=sha256&nonce=DGHFH6EQVYGKP7YHNVEAFQQR5TN4W4JA&quote=r/1RDR4AYACIACzy[...] HTTP/1.1
       Host: example.com
       Accept: application/json

    :query agent_uuid: The UUID of the Agent being verified.
    :query hash_alg: The hash algorithm used by the Keylime agent and TPM.
    :query nonce: The onetime nonce being used for identity verification.
    :query quote: The TPM quoted nonce from the Keylime agent.


    **Example response**:

    .. sourcecode:: json

        {
          "code": 200,
          "status": "Success",
          "results": {
            "valid": 1
          }
        }

    :>json int code: HTTP status code
    :>json string status: Status as string
    :>json object results: Results as a JSON object
    :>json int valid: A boolean 1 for valid, 0 for invalid identity.

