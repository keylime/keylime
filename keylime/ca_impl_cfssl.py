import common
import json
import ConfigParser
import os
import subprocess
import tornado_requests
from M2Crypto import EVP, X509
import secure_mount
import base64
import time

logger = common.init_logging('ca_impl_cfssl')

config = ConfigParser.SafeConfigParser()
config.read(common.CONFIG_FILE)

cfsslproc = None

def post_cfssl(url,data):
    numtries = 0
    maxr = 10
    retry=0.2
    while True:
        try:
            response = tornado_requests.request("POST",url,params=None,data=data,context=None)
            break
        except Exception as e:
            # this is one exception that should return a 'keep going' response
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
    cmd = "cfssl serve -loglevel=5 %s "%cmdline
    env = os.environ.copy()
    env['PATH']=env['PATH']+":/usr/local/bin"

    cfsslproc = subprocess.Popen(cmd,env=env,shell=True)
    if cfsslproc.returncode is not None:
        raise Exception("Unable to launch %: failed with code "%(cmd,cfsslproc.returncode))
    # let cfssl start up
    time.sleep(0.1)
    
def stop_cfssl():
    global cfsslproc
    if cfsslproc is not None:
        cfsslproc.kill()
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
        body = json.loads(response.body)
    finally:
        stop_cfssl()
    
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
    
    # set up config for cfssl server
    cfsslconfig  = {
        "signing": {
            "default": {
                "usages": ["client auth","server auth","key agreement","key encipherment","signing","digital signature","data encipherment"],
                "expiry": "8760h",
                # TODO, this needs to be set to where the CRL will be hosted
                "crl_url": "http://localhost/crl.pem",
            }
        }
    }

    data = json.dumps(csr)
    secdir = common.WORK_DIR+"/secure"
    try:
        secure_mount.mount()
        if not os.path.isdir(secdir):
            os.makedirs(secdir)
            
        # need to temporarily write out the private key with no password
        # to tmpfs 
        ca_pk.save_key('%s/ca-key.pem'%secdir, None)
        with open('%s/cfsslconfig.json'%secdir,'w') as f:
            json.dump(cfsslconfig, f)
            
        cmdline = "-config=%s/cfsslconfig.json"%secdir
        
        priv_key = os.path.abspath("%s/secure/ca-key.pem"%common.WORK_DIR)
        cmdline += " -ca-key %s -ca cacert.crt"%(priv_key)

        start_cfssl(cmdline)
        response =  post_cfssl("http://127.0.0.1:8888/api/v1/cfssl/newcert",data=data)
    finally:
        stop_cfssl()
        os.remove('%s/ca-key.pem'%secdir)
        os.remove('%s/cfsslconfig.json'%secdir)
    
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
    secdir = common.WORK_DIR+"/secure"
    try:
        secure_mount.mount()
        if not os.path.isdir(secdir):
            os.makedirs(secdir)
            
        # need to temporarily write out the private key with no password
        # to tmpfs 
        with open('%s/ca-key.pem'%secdir,'wb') as f:
            f.write(ca_pk)     
        priv_key = os.path.abspath("%s/secure/ca-key.pem"%common.WORK_DIR)
        cmdline = " -ca-key %s -ca cacert.crt"%(priv_key)
       
        start_cfssl(cmdline)
        response =  post_cfssl("http://127.0.0.1:8888/api/v1/cfssl/gencrl",data=data)
    finally:
        stop_cfssl()
        os.remove('%s/ca-key.pem'%secdir)
    
    body = json.loads(response.body)
    
    if body['success']:
        #pk = EVP.load_key_string(str(body['result']['private_key']))
        #cert = X509.load_cert_string(str(body['result']['certificate']))
        #return cert, pk
        retval = base64.b64decode(body['result'])
        with open("my.crl",'wb') as f:
            f.write(retval)
    else:
        raise Exception("Unable to create crl for cert serials %s.  Error: %s"%(serials,body['errors']))
    return retval
    # ./cfssl gencrl revoke ca.pem ca-key.pem | base64 -D > mycrl.der 
    
# mk_cacert()
# mk_signed_cert("", "", "hello", None)