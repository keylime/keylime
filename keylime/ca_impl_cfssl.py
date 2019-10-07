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

import base64
import configparser
import os
import subprocess
import socket
import time
import requests
import shutil
import sys

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

from keylime import common
from keylime import  keylime_logging
from keylime import secure_mount
from M2Crypto import EVP, X509

logger = keylime_logging.init_logging('ca_impl_cfssl')

config = configparser.ConfigParser()
config.read(common.CONFIG_FILE)

cfssl_ip = config.get('general', 'cfssl_ip')
cfssl_port = config.get('general', 'cfssl_port')

cfsslproc = None

def post_cfssl(params,data):
    numtries = 0
    maxr = 10
    retry=0.2
    while True:
        try:
            response = requests.post("http://%s:%s/%s"%(cfssl_ip, cfssl_port,params), json=data, timeout=1)
            break
        except requests.exceptions.ConnectionError as e:
            numtries+=1
            if numtries >= maxr:
                logger.error("Quiting after max number of retries to connect to cfssl server")
                raise e
            logger.info("Connection to cfssl refused %d/%d times, trying again in %f seconds..."%(numtries,maxr,retry))
            time.sleep(retry)
            continue

    if response.status_code!=200:
        raise Exception("Unable to issue CFSSL API command %s: %s"%(params,response.text))
    return response.json()

def start_cfssl(cmdline=""):
    if shutil.which("cfssl") is None:
        logger.error("cfssl binary not found in the path.  Please install cfssl or change the setting \"ca_implementation\" in keylime.conf")
        sys.exit(1)
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
    try:
        start_cfssl()
        body = post_cfssl('api/v1/cfssl/init_ca',csr)
    finally:
        stop_cfssl()

    if body['success']:
        pk_str = body['result']['private_key']
        pk = EVP.load_key_string(body['result']['private_key'].encode('utf-8'))
        cert = X509.load_cert_string(body['result']['certificate'].encode('utf-8'))
        pkey = cert.get_pubkey()

        return pk_str, cert, pk, pkey
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
    secdir = secure_mount.mount()
    try:
        # need to temporarily write out the private key with no password
        # to tmpfs
        ca_pk.save_key('%s/ca-key.pem'%secdir, None)
        with open('%s/cfsslconfig.yml'%secdir,'w') as f:
            json.dump(cfsslconfig, f)

        cmdline = "-config=%s/cfsslconfig.yml"%secdir

        priv_key = os.path.abspath("%s/ca-key.pem"%secdir)
        cmdline += " -ca-key %s -ca cacert.crt"%(priv_key)

        start_cfssl(cmdline)
        body = post_cfssl('api/v1/cfssl/newcert',csr)
    finally:
        stop_cfssl()
        os.remove('%s/ca-key.pem'%secdir)
        os.remove('%s/cfsslconfig.yml'%secdir)

    if body['success']:
        pk = EVP.load_key_string(body['result']['private_key'].encode('utf-8'))
        cert = X509.load_cert_string(body['result']['certificate'].encode("utf-8"))
        return cert, pk
    else:
        raise Exception("Unable to create cert for %s"%name)

def gencrl(serials,cert,ca_pk):
    request = {"certificate": cert,
               "serialNumber": serials,
               "issuingKey": ca_pk,
               "expireTime": ""
               }
    secdir = secure_mount.mount()
    try:
        # need to temporarily write out the private key with no password
        # to tmpfs
        priv_key = os.path.abspath("%s/ca-key.pem"%secdir)
        with open(priv_key,'w') as f:
            f.write(ca_pk)
        cmdline = " -ca-key %s -ca cacert.crt"%(priv_key)

        start_cfssl(cmdline)
        body = post_cfssl('api/v1/cfssl/gencrl',request)

    finally:
        stop_cfssl()
        # replace with srm
        os.remove('%s/ca-key.pem'%secdir)

    if body['success']:
        retval = base64.b64decode(body['result'])
    else:
        raise Exception("Unable to create crl for cert serials %s.  Error: %s"%(serials,body['errors']))
    return retval
    # ./cfssl gencrl revoke ca.pem ca-key.pem | base64 -D > mycrl.der

# mk_cacert()
# mk_signed_cert("", "", "hello", None)
