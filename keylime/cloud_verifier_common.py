import ast
import base64
import time
from typing import Any, Dict, Optional, Union

from keylime import config, crypto, json, keylime_logging
from keylime.agentstates import AgentAttestState, AgentAttestStates, TPMClockInfo
from keylime.common import algorithms
from keylime.db.verifier_db import VerfierMain
from keylime.failure import Component, Event, Failure
from keylime.ima import file_signatures, ima
from keylime.ima.types import RuntimePolicyType
from keylime.tpm import tpm_util
from keylime.tpm.tpm_main import Tpm

# setup logging
logger = keylime_logging.init_logging("cloudverifier_common")

GLOBAL_TPM_INSTANCE: Optional[Tpm] = None
DEFAULT_VERIFIER_ID: str = "default"


def get_tpm_instance() -> Tpm:
    global GLOBAL_TPM_INSTANCE
    if GLOBAL_TPM_INSTANCE is None:
        GLOBAL_TPM_INSTANCE = Tpm()
    return GLOBAL_TPM_INSTANCE


def get_AgentAttestStates() -> AgentAttestStates:
    return AgentAttestStates.get_instance()


def process_quote_response(
    agent: Dict[str, Any],
    mb_policy: Optional[str],
    runtime_policy: RuntimePolicyType,
    json_response: Dict[str, Any],
    agentAttestState: AgentAttestState,
) -> Failure:
    """Validates the response from the Cloud agent.

    This method invokes an Registrar Server call to register, and then check the quote.
    """
    failure = Failure(Component.QUOTE_VALIDATION)
    received_public_key = None
    quote = None
    agent_id = None
    # in case of failure in response content do not continue
    try:
        agent_id = agent["agent_id"]
        received_public_key = json_response.get("pubkey", None)
        quote = json_response["quote"]

        ima_measurement_list = json_response.get("ima_measurement_list", None)
        ima_measurement_list_entry = json_response.get("ima_measurement_list_entry", 0)
        mb_measurement_list = json_response.get("mb_measurement_list", None)
        boottime = json_response.get("boottime", 0)

        logger.debug(
            "received data for agent %s, quote: %s, nonce: %s, public key(b64): %s, ima_measurement_list: %s, ima_measurement_list_entry: %s, measured_boot_log: %s, boottime: %s",
            agent_id,
            quote,
            agent["nonce"],
            base64.b64encode(str(received_public_key).encode("ascii")).decode("ascii"),
            (ima_measurement_list is not None),
            ima_measurement_list_entry,
            (mb_measurement_list is not None),
            boottime,
        )

    except Exception as e:
        failure.add_event("invalid_data", {"message": "parsing agent get quote respone failed", "data": str(e)}, False)
        return failure

    # TODO: Are those separate failures?
    if not isinstance(ima_measurement_list_entry, int):
        raise Exception("ima_measurement_list_entry parameter must be an integer")

    if not isinstance(boottime, int):
        raise Exception("boottime parameter must be an integer")

    # if no public key provided, then ensure we have cached it
    if received_public_key is None:
        if agent.get("public_key", "") == "" or (agent.get("v") and agent.get("b64_encrypted_V", "") == ""):
            logger.error("agent %s did not provide public key and no key or encrypted_v was cached at CV", agent_id)
            failure.add_event(
                "no_pubkey",
                {
                    "message": "agent did not provide public key and no key or encrypted_v was cached at CV",
                    "data": received_public_key,
                },
                False,
            )
            return failure
        agent["provide_V"] = False
        received_public_key = agent["public_key"]

    hash_alg = json_response.get("hash_alg")
    enc_alg = json_response.get("enc_alg")
    sign_alg = json_response.get("sign_alg")

    # Ensure hash_alg is in accept_tpm_hash_alg list
    if (
        not hash_alg
        or not algorithms.is_accepted(hash_alg, agent["accept_tpm_hash_algs"])
        or not algorithms.Hash.is_recognized(hash_alg)
    ):
        logger.error("TPM Quote for agent %s is using an unaccepted hash algorithm: %s", agent_id, hash_alg)
        failure.add_event(
            "invalid_hash_alg",
            {"message": f"TPM Quote is using an unaccepted hash algorithm: {hash_alg}", "data": hash_alg},
            False,
        )
        return failure

    agent["hash_alg"] = hash_alg

    # Ensure enc_alg is in accept_tpm_encryption_algs list
    if not enc_alg or not algorithms.is_accepted(enc_alg, agent["accept_tpm_encryption_algs"]):
        logger.error("TPM Quote for agent %s is using an unaccepted encryption algorithm: %s", agent_id, enc_alg)
        failure.add_event(
            "invalid_enc_alg",
            {"message": f"TPM Quote is using an unaccepted encryption algorithm: {enc_alg}", "data": enc_alg},
            False,
        )
        return failure

    agent["enc_alg"] = enc_alg

    # Ensure sign_alg is in accept_tpm_encryption_algs list
    if not sign_alg or not algorithms.is_accepted(sign_alg, agent["accept_tpm_signing_algs"]):
        logger.error("TPM Quote for agent %s is using an unaccepted signing algorithm: %s", agent_id, sign_alg)
        failure.add_event(
            "invalid_sign_alg",
            {"message": f"TPM Quote is using an unaccepted signing algorithm: {sign_alg}", "data": sign_alg},
            False,
        )
        return failure

    agent["sign_alg"] = sign_alg

    if ima_measurement_list_entry == 0:
        agentAttestState.reset_ima_attestation()
    elif ima_measurement_list_entry != agentAttestState.get_next_ima_ml_entry():
        # If we requested a particular entry number then the agent must return either
        # starting at 0 (handled above) or with the requested number.
        logger.error(
            "Agent %s did not respond with requested next IMA measurement list entry %s but started at %s",
            agent_id,
            agentAttestState.get_next_ima_ml_entry(),
            ima_measurement_list_entry,
        )
        failure.add_event(
            "invalid_ima_entry_nb",
            {
                "message": "Agent did not respond with requested next IMA measurement list entry",
                "got": ima_measurement_list_entry,
                "expected": agentAttestState.get_next_ima_ml_entry(),
            },
            False,
        )
    elif not agentAttestState.is_expected_boottime(boottime):
        # agent sent a list not starting at 0 and provided a boottime that doesn't
        # match the expected boottime, so it must have been rebooted; we would fail
        # attestation this time so we retry with a full attestation next time.
        agentAttestState.reset_ima_attestation()
        return failure

    agentAttestState.set_boottime(boottime)

    ima_keyrings = agentAttestState.get_ima_keyrings()

    # If ima_sign_verification_keys was provided to agent by tenant directly,
    # use that. Otherwise, find keyring in IMA policy.
    # NOTE: the tenant option for ima_sign_verification_keys is deprecated, and
    # will be phased out.
    if agent["ima_sign_verification_keys"]:
        verification_key_string = agent["ima_sign_verification_keys"]
    else:
        verification_key_string = runtime_policy["verification-keys"]

    tenant_keyring = file_signatures.ImaKeyring.from_string(verification_key_string)
    ima_keyrings.set_tenant_keyring(tenant_keyring)

    if agent.get("tpm_clockinfo"):
        agentAttestState.set_tpm_clockinfo(TPMClockInfo.from_dict(agent["tpm_clockinfo"]))

    quote_validation_failure = get_tpm_instance().check_quote(
        agentAttestState,
        agent["nonce"],
        received_public_key,
        quote,
        agent["ak_tpm"],
        agent["tpm_policy"],
        ima_measurement_list,
        runtime_policy,
        algorithms.Hash(hash_alg),
        ima_keyrings,
        mb_measurement_list,
        mb_policy,
        compressed=(agent["supported_version"] == "1.0"),
        count=agent["attestation_count"],
    )  # TODO: change this to always False after initial update
    failure.merge(quote_validation_failure)

    agent["last_received_quote"] = int(time.time())

    if not failure:
        agent["attestation_count"] += 1
        agent["last_successful_attestation"] = int(time.time())
        agent["tpm_clockinfo"] = agentAttestState.get_tpm_clockinfo().to_dict()

        # has public key changed? if so, clear out b64_encrypted_V, it is no longer valid
        if received_public_key != agent.get("public_key", ""):
            agent["public_key"] = received_public_key
            agent["b64_encrypted_V"] = ""
            agent["provide_V"] = True

    # ok we're done
    return failure


def prepare_v(agent: Dict[str, Any]) -> Dict[str, bytes]:
    # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
    if config.INSECURE_DEBUG:
        logger.debug("b64_V (non encrypted): %s", agent["v"])

    if agent.get("b64_encrypted_V", "") != "":
        b64_encrypted_V = agent["b64_encrypted_V"]
        logger.debug("Re-using cached encrypted V")
    else:
        # encrypt V with the public key
        b64_encrypted_V = base64.b64encode(
            crypto.rsa_encrypt(crypto.rsa_import_pubkey(agent["public_key"]), base64.b64decode(agent["v"]))
        )
        agent["b64_encrypted_V"] = b64_encrypted_V

    # logger.debug("b64_encrypted_V:" + b64_encrypted_V)
    post_data = {"encrypted_key": b64_encrypted_V}
    return post_data


def prepare_get_quote(agent: Dict[str, Any]) -> Dict[str, Union[str, int]]:
    """This method encapsulates the action required to invoke a quote request on the Cloud Agent.

    This method is part of the polling loop of the thread launched on Tenant POST.
    """
    agentAttestState = get_AgentAttestStates().get_by_agent_id(agent["agent_id"])
    agent["nonce"] = tpm_util.random_password(20)

    tpm_policy = ast.literal_eval(agent["tpm_policy"])
    params = {
        "nonce": agent["nonce"],
        "mask": tpm_policy["mask"],
        "ima_ml_entry": agentAttestState.get_next_ima_ml_entry(),
    }
    return params


def process_get_status(agent: VerfierMain) -> Dict[str, Any]:
    has_mb_policy = 0
    if agent.mb_policy.mb_policy is not None:
        has_mb_policy = 1

    has_runtime_policy = 0
    if agent.ima_policy.generator and agent.ima_policy.generator > ima.RUNTIME_POLICY_GENERATOR.EmptyAllowList:
        has_runtime_policy = 1

    response = {
        "operational_state": agent.operational_state,
        "v": agent.v,
        "ip": agent.ip,
        "port": agent.port,
        "tpm_policy": agent.tpm_policy,
        "meta_data": agent.meta_data,
        "has_mb_refstate": has_mb_policy,
        "has_runtime_policy": has_runtime_policy,
        "accept_tpm_hash_algs": agent.accept_tpm_hash_algs,
        "accept_tpm_encryption_algs": agent.accept_tpm_encryption_algs,
        "accept_tpm_signing_algs": agent.accept_tpm_signing_algs,
        "hash_alg": agent.hash_alg,
        "enc_alg": agent.enc_alg,
        "sign_alg": agent.sign_alg,
        "verifier_id": agent.verifier_id,
        "verifier_ip": agent.verifier_ip,
        "verifier_port": agent.verifier_port,
        "severity_level": agent.severity_level,
        "last_event_id": agent.last_event_id,
        "attestation_count": agent.attestation_count,
        "last_received_quote": agent.last_received_quote,
        "last_successful_attestation": agent.last_successful_attestation,
    }
    return response


# sign a message with revocation key.  telling of verification problem
def prepare_error(agent: Dict[str, Any], msgtype: str = "revocation", event: Optional[Event] = None) -> Dict[str, Any]:
    # prepare the revocation message:
    revocation = {
        "type": msgtype,
        "ip": agent["ip"],
        "agent_id": agent["agent_id"],
        "port": agent["port"],
        "tpm_policy": agent["tpm_policy"],
        "meta_data": agent["meta_data"],
        "event_time": time.asctime(),
    }
    if event:
        revocation["event_id"] = event.event_id
        revocation["severity_label"] = event.severity_label.name
        revocation["context"] = event.context

    tosend = {"msg": json.dumps(revocation).encode("utf-8")}

    # also need to load up private key for signing revocations
    if agent["revocation_key"] != "":
        signing_key = crypto.rsa_import_privkey(agent["revocation_key"])
        tosend["signature"] = crypto.rsa_sign(signing_key, tosend["msg"])

    else:
        tosend["signature"] = b""
    return tosend


def process_verify_identity_quote(
    agent: VerfierMain,
    quote: str,
    nonce: str,
    hash_alg: str,
    agentAttestState: AgentAttestState,
) -> Failure:
    """Validates a quote for an agent given an identity quote and a nonce.

    This method is useful to validate a quote received from a 3rd party/integration
    """
    failure = Failure(Component.QUOTE_VALIDATION)

    # Ensure hash_alg is recognized
    if not hash_alg or not algorithms.Hash.is_recognized(hash_alg):
        failure.add_event(
            "invalid_hash_alg",
            {"message": f"TPM Quote is using an unrecognized hash algorithm: {hash_alg}", "data": hash_alg},
            False,
        )
        return failure

    public_key = agent.public_key
    ak_tpm = agent.ak_tpm
    assert public_key is not None
    assert ak_tpm is not None

    # check the quote, but policy checks since we only care about identity
    logger.info("Checking identity quote for agent %s", agent.agent_id)
    try:
        quote_failure = get_tpm_instance().check_quote(
            agentAttestState,
            nonce,
            public_key,  # pyright: ignore
            quote,
            ak_tpm,  # pyright: ignore
            {},  # skip tpm_policy check for identity quotes
            None,  # skip ima_measurement_list check for identity quotes
            None,  # skip runtime_policy check for identity quotes
            algorithms.Hash(hash_alg),
            None,  # skip ima_keyrings
            None,  # skip mb_measurement_list
            None,  # skip mb_refstate
            skip_clock_check=True,
            skip_pcr_check=True,
        )
        failure.merge(quote_failure)
    except Exception as e:
        logger.error("Error verifying quote: %s", str(e))
        failure.add_event("invalid_quote", {"message": f"Quote validation failed: {e}"}, False)
        return failure

    # ok we're done
    return failure
