'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import base64
import ssl
import os
import logging

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

from keylime import common
from keylime import keylime_logging
from keylime import crypto
from keylime import httpclient_requests

logger = keylime_logging.init_logging('registrar_client')
context = None

def init_client_tls(config,section):
    global context

    #make this reentrant
    if context is not None:
        return

    if not config.getboolean('general',"enable_tls"):
        logger.warning("TLS is currently disabled, AIKs may not be authentic.")
        return None

    logger.info("Setting up client TLS...")
    tls_dir = config.get(section,'registrar_tls_dir')

    my_cert = config.get(section, 'registrar_my_cert')
    my_priv_key = config.get(section, 'registrar_private_key')
    my_key_pw = config.get(section,'registrar_private_key_pw')

    if tls_dir =='default':
        tls_dir = 'reg_ca'
        my_cert = 'client-cert.crt'
        my_priv_key = 'client-private.pem'

    if tls_dir == 'CV':
        tls_dir = 'cv_ca'
        my_cert = 'client-cert.crt'
        my_priv_key = 'client-private.pem'

    # this is relative path, convert to absolute in WORK_DIR
    if tls_dir[0]!='/':
        tls_dir = os.path.abspath('%s/%s'%(common.WORK_DIR,tls_dir))

    ca_cert = config.get(section,'registrar_ca_cert')

    if ca_cert == 'default':
        ca_path = "%s/cacert.crt"%(tls_dir)
    else:
        ca_path = "%s/%s"%(tls_dir,ca_cert)

    my_cert = "%s/%s"%(tls_dir,my_cert)
    my_priv_key = "%s/%s"%(tls_dir,my_priv_key)

    context = ssl.create_default_context()
    context.load_verify_locations(cafile=ca_path)
    context.check_hostname = config.getboolean('general','tls_check_hostnames')
    context.verify_mode = ssl.CERT_REQUIRED

    if my_key_pw=='default':
        logger.warning("CAUTION: using default password for private key, please set private_key_pw to a strong password")

    context.load_cert_chain(certfile=my_cert,keyfile=my_priv_key,password=my_key_pw)

def getAIK(registrar_ip,registrar_port,agent_id):
    retval = getKeys(registrar_ip,registrar_port,agent_id)
    if retval is None:
        return retval
    else:
        return retval['aik']

def getKeys(registrar_ip,registrar_port,agent_id):
    global context

    #make absolutely sure you don't ask for AIKs unauthenticated
    if context is None or context.verify_mode != ssl.CERT_REQUIRED:
        raise Exception("It is unsafe to use this interface to query AIKs with out server authenticated TLS")

    try:
        params = '/agents/%s'% (agent_id)
        response = httpclient_requests.request("GET", "%s"%(registrar_ip), registrar_port, params=params, context=context)
        response_body = json.loads(response.read().decode())

        if response.status != 200:
            logger.critical("Error: unexpected http response code from Registrar Server: %s"%str(response.status))
            keylime_logging.log_http_response(logger,logging.CRITICAL,response_body)
            return None

        if "results" not in response_body:
            logger.critical("Error: unexpected http response body from Registrar Server: %s"%str(response.status))
            return None

        if "aik" not in response_body["results"]:
            logger.critical("Error: did not receive aik from Registrar Server: %s"%str(response.status))
            return None

        return response_body["results"]

    except AttributeError as e :
        if response == 503 :
            logger.critical("Error: the registrar is not available at %s:%s"%(registrar_ip, registrar_port))
        else :
            logger.exception(e)

    except Exception as e:
        logger.exception(e)

    return None

def doRegisterAgent(registrar_ip,registrar_port,agent_id,tpm_version,pub_ek,ekcert,pub_aik,pub_ek_tpm=None,aik_name=None):
    data = {
    'ek': pub_ek,
    'ekcert': ekcert,
    'aik': pub_aik,
    'aik_name': aik_name,
    'ek_tpm': pub_ek_tpm,
    'tpm_version': tpm_version,
    }
    v_json_message = json.dumps(data)
    params = '/agents/%s'% (agent_id)
    try:
        response = httpclient_requests.request("POST", "%s"%(registrar_ip), registrar_port, params=params, data=v_json_message, context=None)
        response_body = json.loads(response.read().decode("utf-8"))

        if response.status != 200:
            logger.error(f"Error: unexpected http response code from Registrar Server: {response.status}")
            keylime_logging.log_http_response(logger,logging.ERROR,response_body)
            return None

        logger.info(f"Agent registration requested for {agent_id}")

        if "results" not in response_body:
            logger.critical(f"Error: unexpected http response body from Registrar Server: {response.status}")
            return None

        if "blob" not in response_body["results"]:
            logger.critical(f"Error: did not receive blob from Registrar Server: {response.status}")
            return None

        return response_body["results"]["blob"]
    except Exception as e:
        if response == 503:
            logger.error(f"Agent cannot establish connection to registrar at {registrar_ip}:{registrar_port}")
            exit()
        else:
            logger.exception(e)

    return None


def doActivateAgent(registrar_ip,registrar_port,agent_id,key):
    data = {
    'auth_tag': crypto.do_hmac(key,agent_id),
    }
    v_json_message = json.dumps(data)
    params = '/agents/%s/activate'% (agent_id)
    response = httpclient_requests.request("PUT", "%s"%(registrar_ip), registrar_port, params=params, data=v_json_message,  context=None)
    response_body = json.loads(response.read().decode())
    if response.status == 200:
        logger.info("Registration activated for agent %s."%agent_id)
        return True
    else:
        logger.error("Error: unexpected http response code from Registrar Server: " + str(response.status))
        keylime_logging.log_http_response(logger,logging.ERROR,response_body)
        return False

def doActivateVirtualAgent(registrar_ip,registrar_port,agent_id,deepquote):
    data = {
    'deepquote': deepquote,
    }

    v_json_message = json.dumps(data)
    params = '/agents/%s/vactivate'% (agent_id)
    response = httpclient_requests.request("PUT", "%s"%(registrar_ip), registrar_port, params=params, data=v_json_message,  context=None)
    response_body = json.loads(response.read().decode())
    if response.status == 200:
        logger.info("Registration activated for agent %s."%agent_id)
        return True
    else:
        logger.error("Error: unexpected http response code from Registrar Server: " + str(response.status))
        keylime_logging.log_http_response(logger,logging.ERROR,response_body)
        return False


def doRegistrarDelete(registrar_ip,registrar_port, agent_id):
    global context
    params = '/agents/%s'% (agent_id)
    response = httpclient_requests.request("DELETE", "%s"%(registrar_ip), registrar_port, params=params,  context=None)
    response_body = json.loads(response)
    if response.status == 200:
        logger.debug("Registrar deleted.")
    else:
        logger.warn("Status command response: " + str(response.status) + " Unexpected response from registrar.")
        keylime_logging.log_http_response(logger,logging.WARNING,response_body)
