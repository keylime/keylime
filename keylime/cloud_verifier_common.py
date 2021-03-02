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

import json

from keylime import config
from keylime import keylime_logging
from keylime import registrar_client
from keylime import crypto
from keylime import ca_util
from keylime import revocation_notifier
from keylime.tpm.tpm_main import tpm
from keylime.tpm.tpm_abstract import TPM_Utilities
from keylime.common import algorithms
from keylime import ima_file_signatures

# setup logging
logger = keylime_logging.init_logging('cloudverifier_common')

GLOBAL_TPM_INSTANCE = None
def get_tpm_instance():
    global GLOBAL_TPM_INSTANCE
    if GLOBAL_TPM_INSTANCE is None:
        GLOBAL_TPM_INSTANCE = tpm()
    return GLOBAL_TPM_INSTANCE


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
            generatedir = os.path.abspath(
                '%s/%s' % (config.WORK_DIR, generatedir))
        tls_dir = generatedir
        ca_path = "%s/cacert.crt" % (tls_dir)
        if os.path.exists(ca_path):
            logger.info(
                "Existing CA certificate found in %s, not generating a new one" % (tls_dir))
        else:
            logger.info(
                "Generating a new CA in %s and a client certificate for connecting" % tls_dir)
            logger.info("use keylime_ca -d %s to manage this CA" % tls_dir)
            if not os.path.exists(tls_dir):
                os.makedirs(tls_dir, 0o700)
            if my_key_pw == 'default':
                logger.warning(
                    "CAUTION: using default password for CA, please set private_key_pw to a strong password")
            ca_util.setpassword(my_key_pw)
            ca_util.cmd_init(tls_dir)
            ca_util.cmd_mkcert(tls_dir, socket.gethostname())
            ca_util.cmd_mkcert(tls_dir, 'client')

    if tls_dir == 'CV':
        if section != 'registrar':
            raise Exception(
                "You only use the CV option to tls_dir for the registrar not %s" % section)
        tls_dir = os.path.abspath('%s/%s' % (config.WORK_DIR, 'cv_ca'))
        if not os.path.exists("%s/cacert.crt" % (tls_dir)):
            raise Exception(
                "It appears that the verifier has not yet created a CA and certificates, please run the verifier first")

    # if it is relative path, convert to absolute in WORK_DIR
    if tls_dir[0] != '/':
        tls_dir = os.path.abspath('%s/%s' % (config.WORK_DIR, tls_dir))

    if ca_cert == 'default':
        ca_path = "%s/cacert.crt" % (tls_dir)
    elif not os.path.isabs(ca_cert):
        ca_path = "%s/%s" % (tls_dir, ca_cert)
    else:
        ca_path = ca_cert

    if my_cert == 'default':
        my_cert = "%s/%s-cert.crt" % (tls_dir, socket.gethostname())
    elif not os.path.isabs(my_cert):
        my_cert = "%s/%s" % (tls_dir, my_cert)
    else:
        pass

    if my_priv_key == 'default':
        my_priv_key = "%s/%s-private.pem" % (tls_dir, socket.gethostname())
    elif not os.path.isabs(my_priv_key):
        my_priv_key = "%s/%s" % (tls_dir, my_priv_key)

    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
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


def process_quote_response(agent, json_response):
    """Validates the response from the Cloud agent.

    This method invokes an Registrar Server call to register, and then check the quote.
    """
    received_public_key = None
    quote = None
    # in case of failure in response content do not continue
    try:
        received_public_key = json_response.get("pubkey", None)
        quote = json_response["quote"]

        ima_measurement_list = json_response.get("ima_measurement_list", None)
        mb_measurement_list = json_response.get("mb_measurement_list", None)

        logger.debug("received quote:      %s" % quote)
        logger.debug("for nonce:           %s" % agent['nonce'])
        logger.debug("received public key: %s" % received_public_key)
        logger.debug("received ima_measurement_list    %s" %
                     (ima_measurement_list is not None))
        logger.debug("received boot log    %s" %
                     (mb_measurement_list is not None))
    except Exception:
        return None

    # if no public key provided, then ensure we have cached it
    if received_public_key is None:
        if agent.get('public_key', "") == "" or agent.get('b64_encrypted_V', "") == "":
            logger.error(
                "agent did not provide public key and no key or encrypted_v was cached at CV")
            return False
        agent['provide_V'] = False
        received_public_key = agent['public_key']

    if agent.get('registrar_keys', "") == "":
        registrar_client.init_client_tls('cloud_verifier')
        registrar_keys = registrar_client.getKeys(config.get("cloud_verifier", "registrar_ip"), config.get(
            "cloud_verifier", "registrar_port"), agent['agent_id'])
        if registrar_keys is None:
            logger.warning("AIK not found in registrar, quote not validated")
            return False
        agent['registrar_keys'] = registrar_keys

    hash_alg = json_response.get('hash_alg')
    enc_alg = json_response.get('enc_alg')
    sign_alg = json_response.get('sign_alg')

    # Update chosen tpm and algorithms
    agent['hash_alg'] = hash_alg
    agent['enc_alg'] = enc_alg
    agent['sign_alg'] = sign_alg

    # Ensure hash_alg is in accept_tpm_hash_alg list
    if not algorithms.is_accepted(hash_alg, agent['accept_tpm_hash_algs']):
        raise Exception(
            "TPM Quote is using an unaccepted hash algorithm: %s" % hash_alg)

    # Ensure enc_alg is in accept_tpm_encryption_algs list
    if not algorithms.is_accepted(enc_alg, agent['accept_tpm_encryption_algs']):
        raise Exception(
            "TPM Quote is using an unaccepted encryption algorithm: %s" % enc_alg)

    # Ensure sign_alg is in accept_tpm_encryption_algs list
    if not algorithms.is_accepted(sign_alg, agent['accept_tpm_signing_algs']):
        raise Exception(
            "TPM Quote is using an unaccepted signing algorithm: %s" % sign_alg)

    ima_keyring = ima_file_signatures.ImaKeyring.from_string(agent['ima_sign_verification_keys'])
    validQuote = get_tpm_instance().check_quote(
        agent['agent_id'],
        agent['nonce'],
        received_public_key,
        quote,
        agent['registrar_keys']['aik_tpm'],
        agent['tpm_policy'],
        ima_measurement_list,
        agent['allowlist'],
        hash_alg,
        ima_keyring,
        mb_measurement_list,
        {})
    if not validQuote:
        return False

    # set a flag so that we know that the agent was verified once.
    # we only issue notifications for agents that were at some point good
    agent['first_verified'] = True

    # has public key changed? if so, clear out b64_encrypted_V, it is no longer valid
    if received_public_key != agent.get('public_key', ""):
        agent['public_key'] = received_public_key
        agent['b64_encrypted_V'] = ""
        agent['provide_V'] = True

    # ok we're done
    return validQuote


def prepare_v(agent):
    # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
    if config.INSECURE_DEBUG:
        logger.debug("b64_V (non encrypted): " + agent['v'])

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
    agent['nonce'] = TPM_Utilities.random_password(20)

    tpm_policy = ast.literal_eval(agent['tpm_policy'])
    vtpm_policy = ast.literal_eval(agent['vtpm_policy'])

    params = {
        'nonce': agent['nonce'],
        'mask': tpm_policy['mask'],
        'vmask': vtpm_policy['mask'],
    }
    return params


def process_get_status(agent):
    allowlist = ast.literal_eval(agent.allowlist)
    if isinstance(allowlist, dict) and 'allowlist' in allowlist:
        al_len = len(allowlist['allowlist'])
    else:
        al_len = 0
    response = {'operational_state': agent.operational_state,
                'v': agent.v,
                'ip': agent.ip,
                'port': agent.port,
                'tpm_policy': agent.tpm_policy,
                'vtpm_policy': agent.vtpm_policy,
                'meta_data': agent.meta_data,
                'allowlist_len': al_len,
                'accept_tpm_hash_algs': agent.accept_tpm_hash_algs,
                'accept_tpm_encryption_algs': agent.accept_tpm_encryption_algs,
                'accept_tpm_signing_algs': agent.accept_tpm_signing_algs,
                'hash_alg': agent.hash_alg,
                'enc_alg': agent.enc_alg,
                'sign_alg': agent.sign_alg,
                }
    return response


# sign a message with revocation key.  telling of verification problem


def notify_error(agent, msgtype='revocation'):
    if not config.getboolean('cloud_verifier', 'revocation_notifier'):
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

    tosend = {'msg': json.dumps(revocation).encode('utf-8')}

    # also need to load up private key for signing revocations
    if agent['revocation_key'] != "":
        signing_key = crypto.rsa_import_privkey(agent['revocation_key'])
        tosend['signature'] = crypto.rsa_sign(signing_key, tosend['msg'])

    else:
        tosend['signature'] = "none"
    revocation_notifier.notify(tosend)


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
