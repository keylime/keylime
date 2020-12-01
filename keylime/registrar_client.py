'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import os
import logging

import simplejson as json

from keylime import common
from keylime import keylime_logging
from keylime import crypto
from keylime.requests_client import RequestsClient

logger = keylime_logging.init_logging('registrar_client')
tls_cert_info = ()
tls_enabled = False


def init_client_tls(config, section):
    global tls_cert_info
    global tls_enabled

    # make this reentrant
    if tls_cert_info:
        return

    if not config.getboolean('general', "enable_tls"):
        logger.warning("TLS is currently disabled, AIKs may not be authentic.")
        return
    else:
        logger.warning("TLS is enabled.")
        tls_enabled = True

    logger.info("Setting up client TLS...")
    tls_dir = config.get(section, 'registrar_tls_dir')

    my_cert = config.get(section, 'registrar_my_cert')
    my_priv_key = config.get(section, 'registrar_private_key')
    my_key_pw = config.get(section, 'registrar_private_key_pw')

    if tls_dir == 'default':
        tls_dir = 'reg_ca'
        my_cert = 'client-cert.crt'
        my_priv_key = 'client-private.pem'

    if tls_dir == 'CV':
        tls_dir = 'cv_ca'
        my_cert = 'client-cert.crt'
        my_priv_key = 'client-private.pem'

    # this is relative path, convert to absolute in WORK_DIR
    if tls_dir[0] != '/':
        tls_dir = os.path.abspath('%s/%s' % (common.WORK_DIR, tls_dir))

    ca_cert = config.get(section, 'registrar_ca_cert')

    if ca_cert == 'default':
        ca_path = "%s/cacert.crt" % (tls_dir)
    else:
        ca_path = "%s/%s" % (tls_dir, ca_cert)

    tls_cert = "%s/%s" % (tls_dir, my_cert)
    tls_priv_key = "%s/%s" % (tls_dir, my_priv_key)
    tls_cert_info = (tls_cert, tls_priv_key)


def getAIK(registrar_ip, registrar_port, agent_id):
    retval = getKeys(registrar_ip, registrar_port, agent_id)
    if retval is None:
        return retval
    else:
        return retval['aik']


def getKeys(registrar_ip, registrar_port, agent_id):

    # make absolutely sure you don't ask for AIKs unauthenticated
    if not tls_enabled:
        raise Exception(
            "It is unsafe to use this interface to query AIKs with out server authenticated TLS")

    response = None
    try:
        client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled)
        response = client.get(f'/agents/{agent_id}', cert=tls_cert_info, verify=False)
        response_body = response.json()

        if response.status_code != 200:
            logger.critical(
                "Error: unexpected http response code from Registrar Server: %s" % str(response.status_code))
            keylime_logging.log_http_response(logger, logging.CRITICAL, response_body)
            return None

        if "results" not in response_body:
            logger.critical(
                "Error: unexpected http response body from Registrar Server: %s" % str(response.status_code))
            return None

        if "aik" not in response_body["results"]:
            logger.critical(
                "Error: did not receive aik from Registrar Server: %s" % str(response.status_code))
            return None

        return response_body["results"]

    except AttributeError as e:
        if response and response.status_code == 503:
            logger.critical("Error: the registrar is not available at %s:%s" % (
                registrar_ip, registrar_port))
        else:
            logger.exception(e)

    except Exception as e:
        logger.exception(e)

    return None


def doRegisterAgent(registrar_ip, registrar_port, agent_id, tpm_version, pub_ek, ekcert, pub_aik, pub_ek_tpm=None, aik_name=None):
    data = {
        'ek': pub_ek,
        'ekcert': ekcert,
        'aik': pub_aik,
        'aik_name': aik_name,
        'ek_tpm': pub_ek_tpm,
        'tpm_version': tpm_version,
    }
    response = None
    try:
        client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled)
        response = client.post(f'/agents/{agent_id}', cert=tls_cert_info, data=json.dumps(data), verify=False)
        response_body = response.json()

        if response.status_code != 200:
            logger.error(
                f"Error: unexpected http response code from Registrar Server: {response.status_code}")
            keylime_logging.log_http_response(logger, logging.ERROR, response_body)
            return None

        logger.info(f"Agent registration requested for {agent_id}")

        if "results" not in response_body:
            logger.critical(
                f"Error: unexpected http response body from Registrar Server: {response.status_code}")
            return None

        if "blob" not in response_body["results"]:
            logger.critical(
                f"Error: did not receive blob from Registrar Server: {response.status_code}")
            return None

        return response_body["results"]["blob"]
    except Exception as e:
        if response and response.status_code == 503:
            logger.error(
                f"Agent cannot establish connection to registrar at {registrar_ip}:{registrar_port}")
            exit()
        else:
            logger.exception(e)

    return None


def doActivateAgent(registrar_ip, registrar_port, agent_id, key):
    data = {
        'auth_tag': crypto.do_hmac(key, agent_id),
    }
    client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled)
    response = client.put(f'/agents/{agent_id}/activate', cert=tls_cert_info, data=json.dumps(data), verify=False)
    response_body = response.json()

    if response.status_code == 200:
        logger.info("Registration activated for agent %s." % agent_id)
        return True
    else:
        logger.error(
            "Error: unexpected http response code from Registrar Server: " + str(response.status_code))
        keylime_logging.log_http_response(logger, logging.ERROR, response_body)
        return False


def doActivateVirtualAgent(registrar_ip, registrar_port, agent_id, deepquote):
    data = {'deepquote': deepquote}

    client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled)
    response = client.put(f'/agents/{agent_id}/vactivate', cert=tls_cert_info, data=json.dumps(data), verify=False)
    response_body = response.json()

    if response.status_code == 200:
        logger.info("Registration activated for agent %s." % agent_id)
        return True
    else:
        logger.error(
            "Error: unexpected http response code from Registrar Server: " + str(response.status_code))
        keylime_logging.log_http_response(logger, logging.ERROR, response_body)
        return False


def doRegistrarDelete(registrar_ip, registrar_port, agent_id):
    client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled)
    response = client.delete(f'/agents/{agent_id}', cert=tls_cert_info, verify=False)
    response_body = response.json()

    if response.status_code == 200:
        logger.debug("Registrar deleted.")
    else:
        logger.warn("Status command response: " +
                    str(response.status_code) + " Unexpected response from registrar.")
        keylime_logging.log_http_response(logger, logging.WARNING, response_body)
