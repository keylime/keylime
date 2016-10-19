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

import json
import tornado_requests
import traceback
import crypto
import base64
import common
import ssl
import os

logger = common.init_logging('registrar_client')
context = None
    
def noAuthTLSContext(config):
    if not config.getboolean('general',"enable_tls"):
        logger.warning("TLS is currently disabled, AIKs may not be authentic.")
        return
    
    # setup a default SSL context with no cert checking
    global context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

def serverAuthTLSContext(config,section):
    global context
    
    #make this reentrant
    if context is not None:
        return
    
    if not config.getboolean('general',"enable_tls"):
        logger.warning("TLS is currently disabled, AIKs may not be authentic.")
        return None
    
    logger.info("Setting up client TLS...")
    tls_dir = config.get(section,'registrar_tls_dir')
    
    if tls_dir =='default':
        tls_dir = 'reg_ca'
        
    if tls_dir == 'CV':
        tls_dir = 'cv_ca'
        
    # this is relative path, convert to absolute in WORK_DIR
    if tls_dir[0]!='/':
        tls_dir = os.path.abspath('%s/%s'%(common.WORK_DIR,tls_dir))

    ca_cert = config.get(section,'registrar_ca_cert')

    if ca_cert == 'default':
        ca_path = "%s/cacert.crt"%(tls_dir)
    else:
        ca_path = "%s/%s"%(tls_dir,ca_cert)
    
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=ca_path)   
    context.check_hostname = config.getboolean('general','tls_check_hostnames')
    context.verify_mode = ssl.CERT_REQUIRED
    
def getAIK(registrar_ip,registrar_port,instance_id):
    global context
    
    #make absolutely sure you don't ask for AIKs unauthenticated
    if context is not None and context.verify_mode != ssl.CERT_REQUIRED:
        raise Exception("It is unsafe to use this interface to query AIKs with out server authenticated TLS")
    
    try:
        response = tornado_requests.request("GET",
                                            "http://%s:%s/v1/instance_id/%s"%(registrar_ip,registrar_port,instance_id),
                                            context=context)
        
        if response.status_code == 200:
            response_body = response.json()  
            aik = response_body["aik"]
            return aik
        else:
            logger.critical("Error: unexpected http response code from Registrar Server: %s"%str(response.status_code))
            return None 
    except Exception as e:
        logger.critical(traceback.format_exc())
        logger.critical("An unexpected error occurred: " + str(e))
        
    return None

def doRegisterNode(registrar_ip,registrar_port,instance_id,pub_ek,ekcert,pub_aik):
    global context
    data = {
    'command': 'register_node',
    'ek': pub_ek,
    'ekcert': ekcert,
    'aik': pub_aik,
    }
    v_json_message = json.dumps(data)
    
    response = tornado_requests.request("PUT",
                                        "http://%s:%s/v1/instance_id/%s"%(registrar_ip,registrar_port,instance_id),
                                        data=v_json_message,
                                        context=context)

    if response.status_code == 200:
        logger.info("Node registration requested for %s"%instance_id)
        response_body = response.json()  
        return response_body["blob"]
    else:
        logger.error("Error: unexpected http response code from Registrar Server: " + str(response.status_code))
        return None

def doActivateNode(registrar_ip,registrar_port,instance_id,key):
    global context
    data = {
    'command': 'activate_node',
    'auth_tag': crypto.do_hmac(base64.b64decode(key),instance_id),
    }
            
    v_json_message = json.dumps(data)
    
    response = tornado_requests.request("PUT",
                                        "http://%s:%s/v1/instance_id/%s"%(registrar_ip,registrar_port,instance_id),
                                        data=v_json_message,
                                        context=context)

    if response.status_code == 200:
        logger.info("Registration activated for node %s."%instance_id)
    else:
        logger.error("Error: unexpected http response code from Registrar Server: " + str(response.status_code))

def doActivateVirtualNode(registrar_ip,registrar_port,instance_id,deepquote):
    global context
    data = {
    'command': 'activate_virtual_node',
    'deepquote': deepquote,
    }
            
    v_json_message = json.dumps(data)
    
    response = tornado_requests.request("PUT",
                                        "http://%s:%s/v1/instance_id/%s"%(registrar_ip,registrar_port,instance_id),
                                        data=v_json_message,
                                        context=context)

    if response.status_code == 200:
        logger.info("Registration activated for node %s."%instance_id)
    else:
        logger.error("Error: unexpected http response code from Registrar Server: " + str(response.status_code))
    

def doRegisterDelete(registrar_ip,registrar_port, instance_id):
    global context
    response = tornado_requests.request("DELETE", "PUT",
                                        "http://%s:%s/v1/instance_id/%s"%(registrar_ip,registrar_port,instance_id),
                                        context=context)
    
    if response.status_code == 200:
        logger.debug("Registrar deleted.")
    else:
        logger.warn("Status command response: " + str(response.status_code) + " Unexpected response from Cloud Node.") 
