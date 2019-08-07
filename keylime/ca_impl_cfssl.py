'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Copyright 2016 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.
'''

import common
import keylime_logging
import json
import ConfigParser
import os
import subprocess
import tornado_requests
from M2Crypto import EVP, X509
import secure_mount
import base64
import time
import socket

logger = keylime_logging.init_logging('ca_impl_cfssl')

config = ConfigParser.SafeConfigParser()
config.read(common.CONFIG_FILE)

cfsslproc = None

def post_cfssl(url,data):
    numtries = 0
    maxr = 10
    retry=0.05
    while True:
        try:
            response = tornado_requests.request("POST",url,params=None,data=data,context=None)
            break
        except Exception as e:
            if tornado_requests.is_refused(e):
                numtries+=1
                if numtries >= maxr:
                    logger.error("Quiting after max number of retries to connect to cfssl server")
                    raise e
                logger.info("Connection to cfssl refused %d/%d times, trying again in %f seconds..."%(numtries,maxr,retry))
                time.sleep(retry)
                continue
            else:
                raise e
    return response

def start_cfssl(cmdline=""):
    global cfsslproc
    cmd = "cfssl serve -loglevel=1 %s "%cmdline
    env = os.environ.copy()
    env['PATH']=env['PATH']+":/usr/local/bin"
    
    # make sure cfssl isn't running
    os.system('pkill -f cfssl')

    cfsslproc = subprocess.Popen(cmd,env=env,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True)
    if cfsslproc.returncode is not None:
        raise Exception("Unable to launch %: failed with code "%(cmd,cfsslproc.returncode))

    logger.debug("Waiting for cfssl to start...")
    while True:
        line = cfsslproc.stdout.readline()
        if "Now listening on" in line:
            break
    time.sleep(0.2)# give cfssl a little more time to get started
    logger.debug("cfssl started successfully")
    
def stop_cfssl():
    global cfsslproc
    if cfsslproc is not None:
        cfsslproc.kill()
        os.system("pkill -f cfssl")
        cfsslproc = None
    
def mk_cacert():
    csr = {"CN": config.get('ca','cert_ca_name'),
           "key": {
               "algo": "rsa",
               "size": config.getint('ca','cert_bits')
               },
           "names": [
               {
                   "C": config.get('ca','cert_country'),
                   "L": config.get('ca','cert_locality'),
                   "O": config.get('ca','cert_organization'),
                   "OU": config.get('ca','cert_org_unit'),
                   "ST": config.get('ca','cert_state')
                   }
                     ]
           }
    data = json.dumps(csr)
    try:
        start_cfssl()
        response = post_cfssl("http://127.0.0.1:8888/api/v1/cfssl/init_ca",data=data)
    finally:
        stop_cfssl()

    if response.status_code!=200:
        raise Exception("Unable to create CA  Error: %s"%(response.body))
    body = json.loads(response.body)
    
    if body['success']:        
        pk = EVP.load_key_string(str(body['result']['private_key']))
        cert = X509.load_cert_string(str(body['result']['certificate']))
        pkey = cert.get_pubkey()
        
        return cert, pk, pkey
    else:
        raise Exception("Unable to create CA")
    
    
def mk_signed_cert(cacert,ca_pk,name,serialnum):
    csr = {"request": {
            "CN": name,
            "hosts": [
            name,
            ],
           "key": {
               "algo": "rsa",
               "size": config.getint('ca','cert_bits')
               },
           "names": [
               {
                   "C": config.get('ca','cert_country'),
                   "L": config.get('ca','cert_locality'),
                   "O": config.get('ca','cert_organization'),
                   "OU": config.get('ca','cert_org_unit'),
                   "ST": config.get('ca','cert_state')
                   }
                     ]
            }
           }
    
    # check CRL distribution point
    disturl = config.get('ca','cert_crl_dist')
    if disturl == 'default':
        disturl = "http://%s:%s/crl.der"%(socket.getfqdn(),common.CRL_PORT)
    
    # set up config for cfssl server
    cfsslconfig  = {
        "signing": {
            "default": {
                "usages": ["client auth","server auth","key agreement","key encipherment","signing","digital signature","data encipherment"],
                "expiry": "8760h",
                "crl_url": disturl,
            }
        }
    }
    data = json.dumps(csr)
    secdir = secure_mount.mount()
    try:    
        # need to temporarily write out the private key with no password
        # to tmpfs 
        ca_pk.save_key('%s/ca-key.pem'%secdir, None)
        with open('%s/cfsslconfig.json'%secdir,'w') as f:
            json.dump(cfsslconfig, f)
            
        cmdline = "-config=%s/cfsslconfig.json"%secdir
        
        priv_key = os.path.abspath("%s/ca-key.pem"%secdir)
        cmdline += " -ca-key %s -ca cacert.crt"%(priv_key)

        start_cfssl(cmdline)
        response =  post_cfssl("http://127.0.0.1:8888/api/v1/cfssl/newcert",data=data)
    finally:
        stop_cfssl()
        os.remove('%s/ca-key.pem'%secdir)
        os.remove('%s/cfsslconfig.json'%secdir)
        
    if response.status_code!=200:
        raise Exception("Unable to create cert for %s.  Error: %s"%(name,response.body))
    body = json.loads(response.body)
    
    if body['success']:
        pk = EVP.load_key_string(str(body['result']['private_key']))
        cert = X509.load_cert_string(str(body['result']['certificate']))
        return cert, pk
    else:
        raise Exception("Unable to create cert for %s"%name)
    
def gencrl(serials,cert,ca_pk):
    request = {"certificate": cert,
               "serialNumber": serials,
               "issuingKey": ca_pk,
               "expireTime": ""
               }
    data = json.dumps(request)
    secdir = secure_mount.mount()
    try:            
        # need to temporarily write out the private key with no password
        # to tmpfs 
        priv_key = os.path.abspath("%s/ca-key.pem"%secdir)
        with open(priv_key,'wb') as f:
            f.write(ca_pk)     
        cmdline = " -ca-key %s -ca cacert.crt"%(priv_key)
       
        start_cfssl(cmdline)
        response =  post_cfssl("http://127.0.0.1:8888/api/v1/cfssl/gencrl",data=data)
    finally:
        stop_cfssl()
        os.remove('%s/ca-key.pem'%secdir)

    if response.status_code!=200:
        raise Exception("Unable to create crl for cert serials %s.  Error: %s"%(serials,response.body))
    body = json.loads(response.body)
    
    if body['success']:
        #pk = EVP.load_key_string(str(body['result']['private_key']))
        #cert = X509.load_cert_string(str(body['result']['certificate']))
        #return cert, pk
        retval = base64.b64decode(body['result'])
    else:
        raise Exception("Unable to create crl for cert serials %s.  Error: %s"%(serials,body['errors']))
    return retval
    # ./cfssl gencrl revoke ca.pem ca-key.pem | base64 -D > mycrl.der 
    
# mk_cacert()
# mk_signed_cert("", "", "hello", None)