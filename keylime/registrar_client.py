'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''

import base64
import ssl
import os
import logging
import http

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
enable_tls = True

def init_client_tls(config,section):
    global context

    #make this reentrant
    if context is not None:
        return

    if not config.getboolean('general',"enable_tls"):
        logger.warning("TLS is currently disabled, AIKs may not be authentic.")
        global enableTLS
        enableTLS = False
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
    global enableTLS
    #make absolutely sure you don't ask for AIKs unauthenticated
    if enableTLS and (context is None or context.verify_mode != ssl.CERT_REQUIRED):
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
    response = httpclient_requests.request("POST", "%s"%(registrar_ip), registrar_port, params=params, data=v_json_message, context=None)
    if isinstance(response,int):
        logger.error("Error: unexpected http response code from Registrar Server: %d"%response)
        return None

    response_body = json.loads(response.read().decode("utf-8"))

    if response.status != 200:
        logger.error("Error: unexpected http response code from Registrar Server: " + str(response.status))
        keylime_logging.log_http_response(logger,logging.ERROR,response_body)
        return None

    logger.info("Agent registration requested for %s"%agent_id)

    if "results" not in response_body:
        logger.critical("Error: unexpected http response body from Registrar Server: %s"%str(response.status))
        return None

    if "blob" not in response_body["results"]:
        logger.critical("Error: did not receive blob from Registrar Server: %s"%str(response.status))
        return None

    return response_body["results"]["blob"]


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
