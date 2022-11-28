import ast
import base64
import time
from typing import Any, Dict, Optional, Union, cast

from keylime import config, crypto, json, keylime_logging
from keylime.agentstates import AgentAttestState, AgentAttestStates, TPMClockInfo
from keylime.common import algorithms, validators
from keylime.db.verifier_db import VerfierMain
from keylime.failure import Component, Event, Failure
from keylime.ima import file_signatures
from keylime.tpm.tpm_abstract import TPM_Utilities
from keylime.tpm.tpm_main import tpm

# setup logging
logger = keylime_logging.init_logging("cloudverifier_common")

GLOBAL_TPM_INSTANCE: Optional[tpm] = None
DEFAULT_VERIFIER_ID: str = "default"


def get_tpm_instance() -> tpm:
    global GLOBAL_TPM_INSTANCE
    if GLOBAL_TPM_INSTANCE is None:
        GLOBAL_TPM_INSTANCE = tpm()
    return GLOBAL_TPM_INSTANCE


def get_AgentAttestStates() -> AgentAttestStates:
    return AgentAttestStates.get_instance()


def process_quote_response(
    agent: Dict[str, Any], ima_policy, json_response, agentAttestState: AgentAttestState
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
        if agent.get("public_key", "") == "" or agent.get("b64_encrypted_V", "") == "":
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

    # Update chosen tpm and algorithms
    agent["hash_alg"] = hash_alg
    agent["enc_alg"] = enc_alg
    agent["sign_alg"] = sign_alg

    # Ensure hash_alg is in accept_tpm_hash_alg list
    if not algorithms.is_accepted(hash_alg, agent["accept_tpm_hash_algs"]) or not algorithms.Hash.is_recognized(
        hash_alg
    ):
        logger.error("TPM Quote for agent %s is using an unaccepted hash algorithm: %s", agent_id, hash_alg)
        failure.add_event(
            "invalid_hash_alg",
            {"message": f"TPM Quote is using an unaccepted hash algorithm: {hash_alg}", "data": hash_alg},
            False,
        )
        return failure

    # Ensure enc_alg is in accept_tpm_encryption_algs list
    if not algorithms.is_accepted(enc_alg, agent["accept_tpm_encryption_algs"]):
        logger.error("TPM Quote for agent %s is using an unaccepted encryption algorithm: %s", agent_id, enc_alg)
        failure.add_event(
            "invalid_enc_alg",
            {"message": f"TPM Quote is using an unaccepted encryption algorithm: {enc_alg}", "data": enc_alg},
            False,
        )
        return failure

    # Ensure sign_alg is in accept_tpm_encryption_algs list
    if not algorithms.is_accepted(sign_alg, agent["accept_tpm_signing_algs"]):
        logger.error("TPM Quote for agent %s is using an unaccepted signing algorithm: %s", agent_id, sign_alg)
        failure.add_event(
            "invalid_sign_alg",
            {"message": f"TPM Quote is using an unaccepted signing algorithm: {sign_alg}", "data": sign_alg},
            False,
        )
        return failure

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
    tenant_keyring = file_signatures.ImaKeyring.from_string(agent["ima_sign_verification_keys"])
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
        ima_policy,
        algorithms.Hash(hash_alg),
        ima_keyrings,
        mb_measurement_list,
        agent["mb_refstate"],
        compressed=(agent["supported_version"] == "1.0"),
    )  # TODO: change this to always False after initial update
    failure.merge(quote_validation_failure)

    agent["last_received_quote"] = int(time.time())

    if not failure:
        agent["attestation_count"] += 1

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
    agent["nonce"] = TPM_Utilities.random_password(20)

    tpm_policy = ast.literal_eval(agent["tpm_policy"])
    params = {
        "nonce": agent["nonce"],
        "mask": tpm_policy["mask"],
        "ima_ml_entry": agentAttestState.get_next_ima_ml_entry(),
    }
    return params


def process_get_status(agent: VerfierMain) -> Dict[str, Any]:
    agent_id = agent.agent_id

    has_mb_refstate = 0
    try:
        mb_refstate = json.loads(cast(str, agent.mb_refstate))
        if mb_refstate and mb_refstate.keys():
            has_mb_refstate = 1
    except Exception as e:
        logger.warning(
            'Non-fatal problem ocurred while attempting to evaluate agent %s attribute "mb_refstate" (%s). Will just consider the value of this attribute as empty',
            agent_id,
            e.args,
        )
        logger.debug('The contents of the agent %s attribute "mb_refstate" are %s', agent_id, agent.mb_refstate)

    has_ima_policy = 0
    if agent.ima_policy.generator > 1:
        has_ima_policy = 1

    response = {
        "operational_state": agent.operational_state,
        "v": agent.v,
        "ip": agent.ip,
        "port": agent.port,
        "tpm_policy": agent.tpm_policy,
        "meta_data": agent.meta_data,
        "has_mb_refstate": has_mb_refstate,
        "has_ima_policy": has_ima_policy,
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


def validate_ima_policy_data(ima_policy: Optional[str]) -> Optional[str]:
    if ima_policy is None:
        return "No ima_policy provided"

    # validate that the allowlist is proper JSON
    lists = json.loads(ima_policy)

    # Validate that exclude list contains valid regular expressions
    _, err_msg_from_validator = validators.valid_exclude_list(lists.get("exclude"))
    if err_msg_from_validator:
        err_msg_from_validator += " Exclude list regex is misformatted. Please correct the issue and try again."

    return err_msg_from_validator
