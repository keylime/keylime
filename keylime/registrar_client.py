'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import os
import logging
import sys

from keylime import config
from keylime import crypto
from keylime import json
from keylime import keylime_logging
from keylime.requests_client import RequestsClient
from keylime import api_version as keylime_api_version

logger = keylime_logging.init_logging('registrar_client')
tls_cert_info = ()
ca_cert = False
tls_enabled = False
api_version = keylime_api_version.current_version()


def init_client_tls(section):
    global tls_cert_info
    global tls_enabled
    global ca_cert

    # make this reentrant
    if tls_cert_info:
        return

    if not config.getboolean('general', "enable_tls"):
        logger.warning("Warning: TLS is currently disabled, AIKs may not be authentic.")
        return

    logger.warning("TLS is enabled.")
    tls_enabled = True

    logger.info("Setting up client TLS...")
    tls_dir = config.get(section, 'registrar_tls_dir')

    ca_cert = config.get(section, 'registrar_ca_cert')
    my_cert = config.get(section, 'registrar_my_cert')
    my_priv_key = config.get(section, 'registrar_private_key')

    if tls_dir == 'default':
        tls_dir = 'reg_ca'
        ca_cert = 'cacert.crt'
        my_cert = 'client-cert.crt'
        my_priv_key = 'client-private.pem'

    if tls_dir == 'CV':
        tls_dir = 'cv_ca'
        ca_cert = 'cacert.crt'
        my_cert = 'client-cert.crt'
        my_priv_key = 'client-private.pem'

    # this is relative path, convert to absolute in WORK_DIR
    if tls_dir[0] != '/':
        tls_dir = os.path.abspath(os.path.join(config.WORK_DIR, tls_dir))

    if not os.path.isabs(ca_cert):
        ca_cert = os.path.join(tls_dir, ca_cert)

    if os.path.isabs(my_cert):
        tls_cert = my_cert
    else:
        tls_cert = os.path.join(tls_dir, my_cert)
    if os.path.isabs(my_priv_key):
        tls_priv_key = my_priv_key
    else:
        tls_priv_key = os.path.join(tls_dir, my_priv_key)

    tls_cert_info = (tls_cert, tls_priv_key)


def getData(registrar_ip, registrar_port, agent_id):
    # make absolutely sure you don't ask for data that contains AIK keys unauthenticated
    if not tls_enabled:
        raise Exception(
            "It is unsafe to use this interface to query AIKs without server-authenticated TLS.")

    response = None
    try:
        client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled, ignore_hostname=True)
        response = client.get(f'/v{api_version}/agents/{agent_id}', cert=tls_cert_info, verify=ca_cert)
        response_body = response.json()

        if response.status_code == 404:
            logger.critical("Error: could not get agent %s data from Registrar Server: %s", agent_id, response.status_code)
            keylime_logging.log_http_response(logger, logging.CRITICAL, response_body)
            return None

        if response.status_code != 200:
            logger.critical("Error: unexpected http response code from Registrar Server: %s", response.status_code)
            keylime_logging.log_http_response(logger, logging.CRITICAL, response_body)
            return None

        # Check for all values that are consumed by other parts of Keylime
        if "results" not in response_body:
            logger.critical("Error: unexpected http response body from Registrar Server: %s", response.status_code)
            return None

        if "aik_tpm" not in response_body["results"]:
            logger.critical("Error: did not receive AIK from Registrar Server.")
            return None

        if "regcount" not in response_body["results"]:
            logger.critical("Error: did not receive regcount from Registrar Server.")
            return None

        if "ek_tpm" not in response_body["results"]:
            logger.critical("Error: did not receive EK from Registrar Server.")
            return None

        if "ip" not in response_body["results"]:
            logger.critical("Error: did not receive IP from Registrar Server.")
            return None

        if "port" not in response_body["results"]:
            logger.critical("Error: did not receive port from Registrar Server.")
            return None

        return response_body["results"]

    except AttributeError as e:
        if response and response.status_code == 503:
            logger.critical("Error: the registrar is not available at %s:%s", registrar_ip, registrar_port)
        else:
            logger.exception(e)

    except Exception as e:
        logger.exception(e)

    return None


def doRegisterAgent(registrar_ip, registrar_port, agent_id, ek_tpm, ekcert, aik_tpm, mtls_cert=None,
                    contact_ip=None, contact_port=None):
    data = {
        'ekcert': ekcert,
        'aik_tpm': aik_tpm,
    }
    if ekcert is None or ekcert == 'emulator':
        data['ek_tpm'] = ek_tpm

    if mtls_cert is not None:
        data['mtls_cert'] = mtls_cert
    else:
        logger.error("Most actions require the agent to have mTLS enabled, but no cert was provided!")
    if contact_ip is not None:
        data['ip'] = contact_ip
    if contact_port is not None:
        data['port'] = contact_port

    response = None
    try:
        client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled, ignore_hostname=True)
        response = client.post(f'/v{api_version}/agents/{agent_id}', cert=tls_cert_info, data=json.dumps(data), verify=ca_cert)
        response_body = response.json()

        if response.status_code != 200:
            logger.error("Error: unexpected http response code from Registrar Server: %s", response.status_code)
            keylime_logging.log_http_response(logger, logging.ERROR, response_body)
            return None

        logger.info("Agent registration requested for %s", agent_id)

        if "results" not in response_body:
            logger.critical("Error: unexpected http response body from Registrar Server: %s", response.status_code)
            return None

        if "blob" not in response_body["results"]:
            logger.critical("Error: did not receive blob from Registrar Server: %s", response.status_code)
            return None

        return response_body["results"]["blob"]
    except Exception as e:
        if response and response.status_code == 503:
            logger.error("Agent cannot establish connection to registrar at %s:%s", registrar_ip, registrar_port)
            sys.exit()
        else:
            logger.exception(e)

    return None


def doActivateAgent(registrar_ip, registrar_port, agent_id, key):
    data = {
        'auth_tag': crypto.do_hmac(key, agent_id),
    }
    client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled, ignore_hostname=True)
    response = client.put(f'/v{api_version}/agents/{agent_id}/activate', cert=tls_cert_info, data=json.dumps(data), verify=ca_cert)
    response_body = response.json()

    if response.status_code == 200:
        logger.info("Registration activated for agent %s.", agent_id)
        return True

    logger.error(
        "Error: unexpected http response code from Registrar Server: %s", str(response.status_code))
    keylime_logging.log_http_response(logger, logging.ERROR, response_body)
    return False


def doRegistrarDelete(registrar_ip, registrar_port, agent_id):
    client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled, ignore_hostname=True)
    response = client.delete(f'/v{api_version}/agents/{agent_id}', cert=tls_cert_info, verify=ca_cert)
    response_body = response.json()

    if response.status_code == 200:
        logger.debug("Registrar deleted.")
    else:
        logger.warning("Status command response: %s Unexpected response from registrar.", response.status_code)
        keylime_logging.log_http_response(logger, logging.WARNING, response_body)

    return response_body


def doRegistrarList(registrar_ip, registrar_port):
    client = RequestsClient(f'{registrar_ip}:{registrar_port}', tls_enabled, ignore_hostname=True)
    response = client.get(f'/v{api_version}/agents/', cert=tls_cert_info, verify=ca_cert)
    response_body = response.json()

    if response.status_code != 200:
        logger.warning("Registrar returned: %s Unexpected response from registrar.", response.status_code)
        keylime_logging.log_http_response(logger, logging.WARNING, response_body)
        return None

    return response_body
