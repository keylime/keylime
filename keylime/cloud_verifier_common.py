"""
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
"""

import ast
import base64
import os
import ssl
import socket
import time
import sys

import simplejson as json

from keylime import config
from keylime import keylime_logging
from keylime import registrar_client
from keylime import crypto
from keylime import ca_util
from keylime import revocation_notifier
from keylime.agentstates import AgentAttestStates
from keylime.failure import Failure, Component
from keylime.tpm.tpm_main import tpm
from keylime.tpm.tpm_abstract import TPM_Utilities
from keylime.common import algorithms
from keylime import ima_file_signatures

# setup logging
logger = keylime_logging.init_logging('cloudverifier_common')

GLOBAL_TPM_INSTANCE = None
DEFAULT_VERIFIER_ID = "default"


def get_tpm_instance():
    global GLOBAL_TPM_INSTANCE
    if GLOBAL_TPM_INSTANCE is None:
        GLOBAL_TPM_INSTANCE = tpm()
    return GLOBAL_TPM_INSTANCE


def get_AgentAttestStates():
    return AgentAttestStates.get_instance()


def init_mtls(section='cloud_verifier', generatedir='cv_ca'):
    if not config.getboolean('general', "enable_tls"):
        logger.warning(
            "Warning: TLS is currently disabled, keys will be sent in the clear! This should only be used for testing.")
        return None

    logger.info("Setting up TLS...")
    my_cert = config.get(section, 'my_cert')
    ca_cert = config.get(section, 'ca_cert')
    my_priv_key = config.get(section, 'private_key')
    my_key_pw = config.get(section, 'private_key_pw')
    tls_dir = config.get(section, 'tls_dir')

    if tls_dir == 'generate':
        if my_cert != 'default' or my_priv_key != 'default' or ca_cert != 'default':
            raise Exception(
                "To use tls_dir=generate, options ca_cert, my_cert, and private_key must all be set to 'default'")

        if generatedir[0] != '/':
            generatedir = os.path.abspath(os.path.join(config.WORK_DIR,
                                                       generatedir))
        tls_dir = generatedir
        ca_path = "%s/cacert.crt" % (tls_dir)
        if os.path.exists(ca_path):
            logger.info("Existing CA certificate found in %s, not generating a new one", tls_dir)
        else:
            logger.info("Generating a new CA in %s and a client certificate for connecting", tls_dir)
            logger.info("use keylime_ca -d %s to manage this CA", tls_dir)
            if not os.path.exists(tls_dir):
                os.makedirs(tls_dir, 0o700)
            if my_key_pw == 'default':
                logger.warning("CAUTION: using default password for CA, please set private_key_pw to a strong password")
            ca_util.setpassword(my_key_pw)
            ca_util.cmd_init(tls_dir)
            ca_util.cmd_mkcert(tls_dir, socket.gethostname())
            ca_util.cmd_mkcert(tls_dir, 'client')

    if tls_dir == 'CV':
        if section != 'registrar':
            raise Exception(
                "You only use the CV option to tls_dir for the registrar not %s" % section)
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, 'cv_ca'))
        if not os.path.exists("%s/cacert.crt" % (tls_dir)):
            raise Exception(
                "It appears that the verifier has not yet created a CA and certificates, please run the verifier first")

    # if it is relative path, convert to absolute in WORK_DIR
    if tls_dir[0] != '/':
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, tls_dir))

    if ca_cert == 'default':
        ca_path = os.path.join(tls_dir, "cacert.crt")
    elif not os.path.isabs(ca_cert):
        ca_path = os.path.join(tls_dir, ca_cert)
    else:
        ca_path = ca_cert

    if my_cert == 'default':
        my_cert = os.path.join(tls_dir, f"{socket.gethostname()}-cert.crt")
    elif not os.path.isabs(my_cert):
        my_cert = os.path.join(tls_dir, my_cert)
    else:
        pass

    if my_priv_key == 'default':
        my_priv_key = os.path.join(tls_dir,
                                   f"{socket.gethostname()}-private.pem")
    elif not os.path.isabs(my_priv_key):
        my_priv_key = os.path.join(tls_dir, my_priv_key)

    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        if sys.version_info >= (3,7):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            context.options &= ~ssl.OP_NO_TLSv1_2
        context.load_verify_locations(cafile=ca_path)
        context.load_cert_chain(
            certfile=my_cert, keyfile=my_priv_key, password=my_key_pw)
        if (config.has_option(section, 'check_client_cert')
                and config.getboolean(section, 'check_client_cert')):
            context.verify_mode = ssl.CERT_REQUIRED
    except ssl.SSLError as exc:
        if exc.reason == 'EE_KEY_TOO_SMALL':
            logger.error('Higher key strength is required for keylime '
                         'running on this system. If keylime is responsible '
                         'to generate the certificate, please raise the value '
                         'of configuration option [ca]cert_bits, remove '
                         'generated certificate and re-run keylime service')
        raise exc

    return context


def process_quote_response(agent, json_response, agentAttestState) -> Failure:
    """Validates the response from the Cloud agent.

    This method invokes an Registrar Server call to register, and then check the quote.
    """
    failure = Failure(Component.QUOTE_VALIDATION)
    received_public_key = None
    quote = None
    # in case of failure in response content do not continue
    try:
        received_public_key = json_response.get("pubkey", None)
        quote = json_response["quote"]

        ima_measurement_list = json_response.get("ima_measurement_list", None)
        ima_measurement_list_entry = json_response.get("ima_measurement_list_entry", 0)
        mb_measurement_list = json_response.get("mb_measurement_list", None)
        boottime = json_response.get("boottime", 0)

        logger.debug("received quote:      %s", quote)
        logger.debug("for nonce:           %s", agent['nonce'])
        logger.debug("received public key: %s", received_public_key)
        logger.debug("received ima_measurement_list    %s", (ima_measurement_list is not None))
        logger.debug("received ima_measurement_list_entry: %d", ima_measurement_list_entry)
        logger.debug("received boottime: %s", boottime)
        logger.debug("received boot log    %s", (mb_measurement_list is not None))
    except Exception as e:
        failure.add_event("invalid_data", {"message": "parsing agents get quote respone failed", "data": e}, False)
        return failure

    # TODO: Are those separate failures?
    if not isinstance(ima_measurement_list_entry, int):
        raise Exception("ima_measurement_list_entry parameter must be an integer")

    if not isinstance(boottime, int):
        raise Exception("boottime parameter must be an integer")

    # if no public key provided, then ensure we have cached it
    if received_public_key is None:
        if agent.get('public_key', "") == "" or agent.get('b64_encrypted_V', "") == "":
            logger.error("agent did not provide public key and no key or encrypted_v was cached at CV")
            failure.add_event("no_pubkey", "agent did not provide public key and no key or encrypted_v was cached at CV", False)
            return failure
        agent['provide_V'] = False
        received_public_key = agent['public_key']

    if agent.get('registrar_data', "") == "":
        registrar_client.init_client_tls('cloud_verifier')
        registrar_data = registrar_client.getData(config.get("cloud_verifier", "registrar_ip"), config.get(
            "cloud_verifier", "registrar_port"), agent['agent_id'])
        if registrar_data is None:
            logger.warning("AIK not found in registrar, quote not validated")
            failure.add_event("no_aik", "AIK not found in registrar, quote not validated", False)
            return failure
        agent['registrar_data'] = registrar_data

    hash_alg = json_response.get('hash_alg')
    enc_alg = json_response.get('enc_alg')
    sign_alg = json_response.get('sign_alg')

    # Update chosen tpm and algorithms
    agent['hash_alg'] = hash_alg
    agent['enc_alg'] = enc_alg
    agent['sign_alg'] = sign_alg

    # Ensure hash_alg is in accept_tpm_hash_alg list
    if not algorithms.is_accepted(hash_alg, agent['accept_tpm_hash_algs']):
        logger.error(f"TPM Quote is using an unaccepted hash algorithm: {hash_alg}")
        failure.add_event("invalid_hash_alg",
                          {"message": f"TPM Quote is using an unaccepted hash algorithm: {hash_alg}", "data": hash_alg},
                          False)
        return failure

    # Ensure enc_alg is in accept_tpm_encryption_algs list
    if not algorithms.is_accepted(enc_alg, agent['accept_tpm_encryption_algs']):
        logger.error(f"TPM Quote is using an unaccepted encryption algorithm: {enc_alg}")
        failure.add_event("invalid_enc_alg",
                          {"message": f"TPM Quote is using an unaccepted encryption algorithm: {enc_alg}", "data": enc_alg},
                          False)
        return failure

    # Ensure sign_alg is in accept_tpm_encryption_algs list
    if not algorithms.is_accepted(sign_alg, agent['accept_tpm_signing_algs']):
        logger.error(f"TPM Quote is using an unaccepted signing algorithm: {sign_alg}")
        failure.add_event("invalid_sign_alg",
                          {"message": f"TPM Quote is using an unaccepted signing algorithm: {sign_alg}", "data": {sign_alg}},
                          False)
        return failure

    if ima_measurement_list_entry == 0:
        agentAttestState.reset_ima_attestation()
    elif ima_measurement_list_entry != agentAttestState.get_next_ima_ml_entry():
        # If we requested a particular entry number then the agent must return either
        # starting at 0 (handled above) or with the requested number.
        logger.error("Agent did not respond with requested next IMA measurement list entry "
                     f"{agentAttestState.get_next_ima_ml_entry()} but started at {ima_measurement_list_entry}")
        failure.add_event("invalid_ima_entry_nb",
                          {"message": "Agent did not respond with requested next IMA measurement list entry",
                           "got": ima_measurement_list_entry, "expected": agentAttestState.get_next_ima_ml_entry()},
                          False)
    elif not agentAttestState.is_expected_boottime(boottime):
        # agent sent a list not starting at 0 and provided a boottime that doesn't
        # match the expected boottime, so it must have been rebooted; we would fail
        # attestation this time so we retry with a full attestation next time.
        agentAttestState.reset_ima_attestation()
        return failure

    agentAttestState.set_boottime(boottime)

    ima_keyring = ima_file_signatures.ImaKeyring.from_string(agent['ima_sign_verification_keys'])
    quote_validation_failure = get_tpm_instance().check_quote(
        agentAttestState,
        agent['nonce'],
        received_public_key,
        quote,
        agent['registrar_data']['aik_tpm'],
        agent['tpm_policy'],
        ima_measurement_list,
        agent['allowlist'],
        hash_alg,
        ima_keyring,
        mb_measurement_list,
        agent['mb_refstate'])
    failure.merge(quote_validation_failure)

    if not failure:
        # set a flag so that we know that the agent was verified once.
        # we only issue notifications for agents that were at some point good
        agent['first_verified'] = True

        # has public key changed? if so, clear out b64_encrypted_V, it is no longer valid
        if received_public_key != agent.get('public_key', ""):
            agent['public_key'] = received_public_key
            agent['b64_encrypted_V'] = ""
            agent['provide_V'] = True

    # ok we're done
    return failure


def prepare_v(agent):
    # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
    if config.INSECURE_DEBUG:
        logger.debug("b64_V (non encrypted): %s", agent['v'])

    if agent.get('b64_encrypted_V', "") != "":
        b64_encrypted_V = agent['b64_encrypted_V']
        logger.debug("Re-using cached encrypted V")
    else:
        # encrypt V with the public key
        b64_encrypted_V = base64.b64encode(crypto.rsa_encrypt(
            crypto.rsa_import_pubkey(agent['public_key']), base64.b64decode(agent['v'])))
        agent['b64_encrypted_V'] = b64_encrypted_V

    # logger.debug("b64_encrypted_V:" + b64_encrypted_V)
    post_data = {
        'encrypted_key': b64_encrypted_V
    }
    v_json_message = json.dumps(post_data)
    return v_json_message


def prepare_get_quote(agent):
    """This method encapsulates the action required to invoke a quote request on the Cloud Agent.

    This method is part of the polling loop of the thread launched on Tenant POST.
    """
    agentAttestState = get_AgentAttestStates().get_by_agent_id(agent['agent_id'])
    agent['nonce'] = TPM_Utilities.random_password(20)

    tpm_policy = ast.literal_eval(agent['tpm_policy'])
    vtpm_policy = ast.literal_eval(agent['vtpm_policy'])

    params = {
        'nonce': agent['nonce'],
        'mask': tpm_policy['mask'],
        'vmask': vtpm_policy['mask'],
        'ima_ml_entry': agentAttestState.get_next_ima_ml_entry(),
    }
    return params


def process_get_status(agent):
    allowlist = ast.literal_eval(agent.allowlist)
    if isinstance(allowlist, dict) and 'allowlist' in allowlist:
        al_len = len(allowlist['allowlist'])
    else:
        al_len = 0

    try :
        mb_refstate = ast.literal_eval(agent.mb_refstate)
    except Exception as e:
        logger.warning('Non-fatal problem ocurred while attempting to evaluate agent attribute "mb_refstate" (%s). Will just consider the value of this attribute to be "None"', e.args)
        mb_refstate = None
        logger.debug('The contents of the agent attribute "mb_refstate" are %s', agent.mb_refstate)

    if isinstance(mb_refstate, dict) and 'mb_refstate' in mb_refstate:
        mb_refstate_len = len(mb_refstate['mb_refstate'])
    else:
        mb_refstate_len = 0
    response = {'operational_state': agent.operational_state,
                'v': agent.v,
                'ip': agent.ip,
                'port': agent.port,
                'tpm_policy': agent.tpm_policy,
                'vtpm_policy': agent.vtpm_policy,
                'meta_data': agent.meta_data,
                'allowlist_len': al_len,
                'mb_refstate_len': mb_refstate_len,
                'accept_tpm_hash_algs': agent.accept_tpm_hash_algs,
                'accept_tpm_encryption_algs': agent.accept_tpm_encryption_algs,
                'accept_tpm_signing_algs': agent.accept_tpm_signing_algs,
                'hash_alg': agent.hash_alg,
                'enc_alg': agent.enc_alg,
                'sign_alg': agent.sign_alg,
                'verifier_id' : agent.verifier_id,
                'verifier_ip' : agent.verifier_ip,
                'verifier_port' : agent.verifier_port,
                'severity_level': agent.severity_level,
                'last_event_id': agent.last_event_id
                }
    return response


# sign a message with revocation key.  telling of verification problem


def notify_error(agent, msgtype='revocation', event=None):
    send_mq = config.getboolean('cloud_verifier', 'revocation_notifier')
    send_webhook = config.getboolean('cloud_verifier', 'revocation_notifier_webhook', False)
    if not (send_mq or send_webhook):
        return

    # prepare the revocation message:
    revocation = {'type': msgtype,
                  'ip': agent['ip'],
                  'agent_id': agent['agent_id'],
                  'port': agent['port'],
                  'tpm_policy': agent['tpm_policy'],
                  'vtpm_policy': agent['vtpm_policy'],
                  'meta_data': agent['meta_data'],
                  'event_time': time.asctime()}
    if event:
        revocation['event_id'] = event.event_id
        revocation['severity_label'] = event.severity_label.name
        revocation['context'] = event.context

    tosend = {'msg': json.dumps(revocation).encode('utf-8')}

    # also need to load up private key for signing revocations
    if agent['revocation_key'] != "":
        signing_key = crypto.rsa_import_privkey(agent['revocation_key'])
        tosend['signature'] = crypto.rsa_sign(signing_key, tosend['msg'])

    else:
        tosend['signature'] = "none"
    if send_mq:
        revocation_notifier.notify(tosend)
    if send_webhook:
        revocation_notifier.notify_webhook(tosend)


def validate_agent_data(agent_data):
    if agent_data is None:
        return False, None

    # validate that the allowlist is proper JSON
    lists = json.loads(agent_data['allowlist'])

    # Validate exlude list contains valid regular expressions
    is_valid, _, err_msg = config.valid_exclude_list(lists.get('exclude'))
    if not is_valid:
        err_msg += " Exclude list regex is misformatted. Please correct the issue and try again."

    return is_valid, err_msg
