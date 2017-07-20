#!/usr/bin/python

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
import base64
import ConfigParser
import common
import registrar_client
import tpm_quote
import sys
import tpm_initialize
import argparse
import crypto
import traceback
import time
import user_data_encrypt
import ca_util
import os
import ssl
import tornado_requests
import hashlib
import ima
import zipfile
import cStringIO
import StringIO
import tpm_exec
import logging
import subprocess

#setup logging
logger = common.init_logging('tenant')

# setup config
config = ConfigParser.RawConfigParser()
config.read(common.CONFIG_FILE)

class Tenant():
    """Simple command processor example."""
    
    config = None
    
    cloudverifier_ip = None
    cloudverifier_port = None
        
    cloudnode_ip = None
    cloudnode_port = None
    
    registrar_ip = None
    registrar_port = None
    
    webapp_ip = None
    webapp_port = None

    uuid_service_generate_locally = None
    node_uuid = None
    
    K = None
    V = None
    U = None
    auth_tag = None
    
    tpm_policy = None
    vtpm_policy = {}
    metadata = {}
    ima_whitelist = {}
    revocation_key = ""
    
    payload = None
    
    context = None
    
    def __init__(self):
        self.cloudverifier_port = config.get('general', 'cloudverifier_port')
        self.cloudnode_port = config.get('general', 'cloudnode_port')
        self.registrar_port = config.get('general', 'registrar_tls_port')
        self.webapp_port = config.get('general', 'webapp_port')
        
        self.cloudverifier_ip = config.get('tenant', 'cloudverifier_ip')
        self.registrar_ip = config.get('general', 'registrar_ip')
        self.webapp_ip = config.get('general', 'webapp_ip')
        
        if config.getboolean('general',"enable_tls"):
            self.context = self.get_tls_context()
        else:
            logger.warning("TLS is currently disabled, keys will be sent in the clear! Should only be used for testing")
            self.context = None
            
    
    def get_tls_context(self):
        ca_cert = config.get('tenant', 'ca_cert')
        my_cert = config.get('tenant', 'my_cert')
        my_priv_key = config.get('tenant', 'private_key')
        my_key_pw = config.get('tenant','private_key_pw')
        
        tls_dir = config.get('tenant','tls_dir')
        
        if tls_dir == 'default':
            ca_cert = 'cacert.crt'
            my_cert = 'client-cert.crt'
            my_priv_key = 'client-private.pem'
            tls_dir = 'cv_ca'
            
        # this is relative path, convert to absolute in WORK_DIR
        if tls_dir[0]!='/':
            tls_dir = os.path.abspath('%s/%s'%(common.WORK_DIR,tls_dir))
            
        if my_key_pw=='default':
            logger.warning("CAUTION: using default password for private key, please set private_key_pw to a strong password")
            
        logger.info("Setting up client TLS in %s"%(tls_dir))
        
        ca_path = "%s/%s"%(tls_dir,ca_cert)
        my_cert = "%s/%s"%(tls_dir,my_cert)
        my_priv_key = "%s/%s"%(tls_dir,my_priv_key)
    
        context = ssl.create_default_context()
        context.load_verify_locations(cafile=ca_path)   
        context.load_cert_chain(certfile=my_cert,keyfile=my_priv_key,password=my_key_pw)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = config.getboolean('general','tls_check_hostnames')
        return context
    
    def init_add(self, args):
        # command line options can overwrite config values
        if "node_ip" in args:
            self.cloudnode_ip = args["node_ip"]
        
        # Make sure all keys exist in dictionary 
        if "file" not in args: 
            args["file"] = None
        if "keyfile" not in args: 
            args["keyfile"] = None
        if "payload" not in args: 
            args["payload"] = None
        if "ca_dir" not in args: 
            args["ca_dir"] = None
        if "incl_dir" not in args: 
            args["incl_dir"] = None
        if "ca_dir_pw" not in args: 
            args["ca_dir_pw"] = None
        
        
        # Set up PCR values 
        tpm_policy = config.get('tenant', 'tpm_policy')
        if "tpm_policy" in args and args["tpm_policy"] is not None: 
            tpm_policy = args["tpm_policy"]
        self.tpm_policy = tpm_quote.readPolicy(tpm_policy)
        logger.info("TPM PCR Mask from policy is %s"%self.tpm_policy['mask'])
        
        vtpm_policy = config.get('tenant', 'vtpm_policy')
        if "vtpm_policy" in args and args["vtpm_policy"] is not None: 
            vtpm_policy = args["vtpm_policy"]
        self.vtpm_policy = tpm_quote.readPolicy(vtpm_policy)
        logger.info("vTPM PCR Mask from policy is %s"%self.vtpm_policy['mask'])
        
        
        # Read command-line path string IMA whitelist 
        wl_data = None
        if "ima_whitelist" in args and args["ima_whitelist"] is not None:
            
            # Auto-enable IMA (or-bit mask)
            self.tpm_policy['mask'] = "0x%X"%(int(self.tpm_policy['mask'],0) + (1 << common.IMA_PCR))
            
            if type(args["ima_whitelist"]) in [str,unicode]:
                if args["ima_whitelist"] == "default":
                    args["ima_whitelist"] = config.get('tenant', 'ima_whitelist')
                wl_data = ima.read_whitelist(args["ima_whitelist"])
            elif type(args["ima_whitelist"]) is list:
                wl_data = args["ima_whitelist"]
            else:
                logger.error("Invalid whitelist provided")
                raise Exception("Invalid whitelist provided")
        
        # Read command-line path string IMA exclude list 
        excl_data = None
        if "ima_exclude" in args and args["ima_exclude"] is not None:
            if type(args["ima_exclude"]) in [str,unicode]:
                if args["ima_exclude"] == "default":
                    args["ima_exclude"] = config.get('tenant', 'ima_excludelist')
                excl_data = ima.read_excllist(args["ima_exclude"])
            elif type(args["ima_exclude"]) is list:
                excl_data = args["ima_exclude"]
            else:
                logger.error("Invalid exclude list provided")
                raise Exception("Invalid exclude list provided")
        
        # Set up IMA 
        if tpm_quote.check_mask(self.tpm_policy['mask'],common.IMA_PCR) or \
            tpm_quote.check_mask(self.vtpm_policy['mask'],common.IMA_PCR):
            
            # Process IMA whitelists 
            self.ima_whitelist = ima.process_whitelists(wl_data,excl_data)
            
        
        # if none
        if (args["file"] is None and 
            args["keyfile"] is None and 
            args["ca_dir"] is None):
            logger.error("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
            raise Exception("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")

        if args["keyfile"] is not None:
            if args["file"] is not None or args["ca_dir"] is not None:
                logger.error("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
                raise Exception("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
            
            # read the keys in
            if type(args["keyfile"]) is dict and "data" in args["keyfile"]:
                if type(args["keyfile"]["data"]) is list and len(args["keyfile"]["data"]) == 1:
                    keyfile = args["keyfile"]["data"][0]
                    if keyfile is None:
                        logger.error("Invalid key file contents")
                        raise Exception("Invalid key file contents")
                    f = StringIO.StringIO(keyfile)
                else:
                    logger.error("Invalid key file provided")
                    raise Exception("Invalid key file provided")
            else:
                f = open(args["keyfile"],'r')
            self.K = base64.b64decode(f.readline())
            self.U = base64.b64decode(f.readline())
            self.V = base64.b64decode(f.readline())
            f.close()
            
            # read the payload in (opt.)
            if type(args["payload"]) is dict and "data" in args["payload"]:
                if type(args["payload"]["data"]) is list and len(args["payload"]["data"]) > 0:
                    self.payload = args["payload"]["data"][0]
            else: 
                if args["payload"] is not None:
                    f = open(args["payload"],'r')
                    self.payload = f.read()
                    f.close() 
        
        if args["file"] is not None:
            if args["keyfile"] is not None or args["ca_dir"] is not None:
                logger.error("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
                raise Exception("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
                
            if type(args["file"]) is dict and "data" in args["file"]:
                if type(args["file"]["data"]) is list and len(args["file"]["data"]) > 0:
                    contents = args["file"]["data"][0]
                    if contents is None:
                        logger.error("Invalid file payload contents")
                        raise Exception("Invalid file payload contents")
                else:
                    logger.error("Invalid file payload provided")
                    raise Exception("Invalid file payload provided")
            else:
                with open(args["file"],'r') as f:
                    contents = f.read()
            ret = user_data_encrypt.encrypt(contents)
            self.K = ret['k']
            self.U = ret['u']
            self.V = ret['v']
            self.payload = ret['ciphertext']
        
        if args["ca_dir"] is None and args["incl_dir"] is not None:
            logger.error("--include option is only valid when used with --cert")
            raise Exception("--include option is only valid when used with --cert")    
        if args["ca_dir"] is not None:
            if args["file"] is not None or args["keyfile"] is not None:
                logger.error("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
                raise Exception("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
            if args["ca_dir"]=='default':
                args["ca_dir"] = common.CA_WORK_DIR
            
            if "ca_dir_pw" in args and args["ca_dir_pw"] is not None:
                ca_util.setpassword(args["ca_dir_pw"])
            
            if not os.path.exists(args["ca_dir"]):
                logger.warning(" CA directory does not exist.  Creating...")
                ca_util.cmd_init(args["ca_dir"])
            
            
            if not os.path.exists("%s/%s-private.pem"%(args["ca_dir"],self.node_uuid)):
                ca_util.cmd_mkcert(args["ca_dir"],self.node_uuid)
                
            cert_pkg,serial = ca_util.cmd_certpkg(args["ca_dir"],self.node_uuid)
            
            # support revocation
            if not os.path.exists("%s/RevocationNotifier-private.pem"%args["ca_dir"]):
                ca_util.cmd_mkcert(args["ca_dir"],"RevocationNotifier")
            rev_package,_ = ca_util.cmd_certpkg(args["ca_dir"],"RevocationNotifier")
            
            # extract public and private keys from package
            sf = cStringIO.StringIO(rev_package)
            with zipfile.ZipFile(sf) as zf:
                privkey = zf.read("RevocationNotifier-private.pem")
                cert = zf.read("RevocationNotifier-cert.crt")
            
            # put the cert of the revoker into the cert package
            sf = StringIO.StringIO(cert_pkg)
            with zipfile.ZipFile(sf,'a',compression=zipfile.ZIP_STORED) as zf:
                zf.writestr('RevocationNotifier-cert.crt',cert)
                
                # add additional files to zip
                if args["incl_dir"] is not None:
                    if type(args["incl_dir"]) is dict and "data" in args["incl_dir"] and "name" in args["incl_dir"]:
                        if type(args["incl_dir"]["data"]) is list and type(args["incl_dir"]["name"]) is list:
                            if len(args["incl_dir"]["data"]) != len(args["incl_dir"]["name"]):
                                logger.error("Invalid incl_dir provided")
                                raise Exception("Invalid incl_dir provided")
                            for i in range(len(args["incl_dir"]["data"])):
                                zf.writestr(os.path.basename(args["incl_dir"]["name"][i]),args["incl_dir"]["data"][i])
                    else:
                        files = next(os.walk(args["incl_dir"]))[2]
                        for filename in files:
                            with open("%s/%s"%(args["incl_dir"],filename),'rb') as f:
                                zf.writestr(os.path.basename(f.name),f.read())
                  
            cert_pkg = sf.getvalue()
            
            # put the private key into the data to be send to the CV
            self.revocation_key = privkey
            
            # encrypt up the cert package
            ret = user_data_encrypt.encrypt(cert_pkg)
            self.K = ret['k']
            self.U = ret['u']
            self.V = ret['v']
            self.metadata = {'cert_serial':serial}
            self.payload = ret['ciphertext']
            
        if self.payload is not None and len(self.payload)>config.getint('tenant','max_payload_size'):
            raise Exception("Payload size %s exceeds max size %d"%(len(self.payload),config.getint('tenant','max_payload_size'))) 
    
    def preloop(self):
        # encrypt the node UUID as a check for delivering the correct key
        self.auth_tag = crypto.do_hmac(self.K,self.node_uuid)
        # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
        if common.DEVELOP_IN_ECLIPSE:
            logger.debug("K:" + base64.b64encode(self.K))
            logger.debug("V:" + base64.b64encode(self.V))
            logger.debug("U:" + base64.b64encode(str(self.U)))
            logger.debug("Auth Tag: " + self.auth_tag)

    def validate_tpm_quote(self,public_key, quote):
        registrar_client.init_client_tls(config,'tenant')
        reg_keys = registrar_client.getKeys(self.cloudverifier_ip,self.registrar_port,self.node_uuid)
        if reg_keys is None:
            logger.warning("AIK not found in registrar, quote not validated")
            return False
        
        if not tpm_quote.check_quote(self.nonce,public_key,quote,reg_keys['aik']):
            return False
        
        # check ek with optional script:
        script = config.get('tenant', 'ek_check_script')
        if script is not "":
            logger.info("Checking EK with script %s"%script)
            #now we need to exec the script with the ek and ek cert in vars
            env = os.environ.copy()
            env['NODE_UUID']=self.node_uuid
            env['EK'] = reg_keys['ek']
            if reg_keys['ekcert'] is not None:
                env['EK_CERT'] = reg_keys['ekcert']
            else:
                env['EK_CERT']=""
                
            env['PROVKEYS']=json.dumps(reg_keys.get('provider_keys',{}))
            proc= subprocess.Popen(script,env=env,shell=True,cwd=common.WORK_DIR,
                                    stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            retval = proc.wait()
            
            if retval != 0:
                logger.error("External check script failed to validate EK")
                while True:
                    line = proc.stdout.readline()
                    if line=="":
                        break
                    logger.debug("ek_check output: %s"%line.strip())
                return False
        
        return True

    def do_cv(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        b64_v = base64.b64encode(self.V)
        logger.debug("b64_v:" + b64_v)
        data = {
            'v': b64_v,
            'cloudnode_ip': self.cloudnode_ip,
            'cloudnode_port': self.cloudnode_port,
            'tpm_policy': json.dumps(self.tpm_policy),
            'vtpm_policy':json.dumps(self.vtpm_policy),
            'ima_whitelist':json.dumps(self.ima_whitelist),
            'metadata':json.dumps(self.metadata),
            'revocation_key':self.revocation_key,
        }
        
        json_message = json.dumps(data)
        response = tornado_requests.request("POST","http://%s:%s/v2/instances/%s"%(self.cloudverifier_ip,self.cloudverifier_port,self.node_uuid),data=json_message,context=self.context)
        if response.status_code == 409:
            # this is a conflict, delete first then re-add
            logger.warning("Node already existed at CV.  Deleting and re-adding...")
            self.do_cvdelete()
            self.do_cv()
        elif response.status_code != 200:
            common.log_http_response(logger,logging.ERROR,response.json())
            raise Exception("POST command response: %d Unexpected response from Cloud Verifier: %s"%(response.status_code,response.body))


    def do_cvstatus(self,listing=False):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        node_uuid = ""
        if not listing:
            node_uuid=self.node_uuid

        response = tornado_requests.request("GET", "http://%s:%s/v2/instances/%s"%(self.cloudverifier_ip,self.cloudverifier_port,node_uuid),context=self.context)
        if response.status_code != 200:
            logger.error("Status command response: %d Unexpected response from Cloud Verifier."%response.status_code)
            common.log_http_response(logger,logging.ERROR,response.json())
        else:
            logger.info("Node Status %d: %s"%(response.status_code,response.json()))

    def do_cvdelete(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        
        response = tornado_requests.request("DELETE","http://%s:%s/v2/instances/%s"%(self.cloudverifier_ip,self.cloudverifier_port,self.node_uuid),context=self.context)
        if response.status_code != 200:
            logger.error("Delete command response: %d Unexpected response from Cloud Verifier."%response.status_code)
            common.log_http_response(logger,logging.ERROR,response.json())
        else:
            logger.info("Node %s deleted from CV"%(self.node_uuid))
            
    def do_cvreactivate(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        response = tornado_requests.request("PUT","http://%s:%s/v2/instances/%s"%(self.cloudverifier_ip,self.cloudverifier_port,self.node_uuid),context=self.context,data=b'')
        if response.status_code != 200:
            logger.error("Update command response: %d Unexpected response from Cloud Verifier."%response.status_code)
            common.log_http_response(logger,logging.ERROR,response.json())
        else:
            logger.info("Node %s re-activated"%(self.node_uuid))
        
    def do_quote(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        self.nonce = tpm_initialize.random_password(20)
        
        numtries = 0
        while True:
            # Get quote 
            try:
                response = tornado_requests.request("GET",
                                            "http://%s:%s/v2/quotes/identity/nonce/%s/"%(self.cloudnode_ip,self.cloudnode_port,self.nonce))
            except Exception as e:
                # this is one exception that should return a 'keep going' response
                if tornado_requests.is_refused(e):
                    numtries+=1
                    maxr = config.getint('tenant','max_retries')
                    if numtries >= maxr:
                        logger.error("Quitting after max number of retries to connect to %s"%(self.cloudnode_ip))
                        raise e
                    retry  = config.getfloat('tenant','retry_interval')
                    logger.info("Connection to %s refused %d/%d times, trying again in %f seconds..."%(self.cloudnode_ip,numtries,maxr,retry))
                    time.sleep(retry)
                    continue
                else:
                    raise e
            
            
            if response.status_code != 200:
                logger.error("Status command response: %d Unexpected response from Cloud Node."%response.status_code)
                break
            
            response_body = response.json()
            
            if "results" not in response_body:
                logger.critical("Error: unexpected http response body from Cloud Node: %s"%str(response.status_code))
                break
            
            quote = response_body["results"]["quote"]
            logger.debug("cnquote received quote:" + quote)
            
            public_key = response_body["results"]["pubkey"]
            logger.debug("cnquote received public key:" + public_key)
            
            if not self.validate_tpm_quote(public_key, quote):
                logger.error("TPM Quote from cloud node is invalid for nonce: %s"%self.nonce)
                break
        
            logger.info("Quote from %s validated"%self.cloudnode_ip)

            # encrypt U with the public key
            encrypted_U = crypto.rsa_encrypt(crypto.rsa_import_pubkey(public_key),str(self.U))

            b64_encrypted_u = base64.b64encode(encrypted_U)
            logger.debug("b64_encrypted_u: " + b64_encrypted_u)
            data = {
                      'encrypted_key': b64_encrypted_u,
                      'auth_tag': self.auth_tag
                    }
            
            if self.payload is not None:
                data['payload']=self.payload
            
            u_json_message = json.dumps(data)
            
            #post encrypted U back to CloudNode
            response = tornado_requests.request("POST", "http://%s:%s/v2/keys/ukey"%(self.cloudnode_ip,self.cloudnode_port),data=u_json_message)
            
            if response.status_code != 200:
                logger.error("Posting of Encrypted U to the Cloud Node failed with response code %d" %response.status_code)
                common.log_http_response(logger,logging.ERROR,response_body)
                break
            
            break
       
    def do_verify(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        challenge = tpm_initialize.random_password(20)
        
        numtries = 0
        while True: 
            try:
                response = tornado_requests.request("GET",
                                            "http://%s:%s/v2/keys/verify/challenge/%s/"%(self.cloudnode_ip,self.cloudnode_port,challenge))
            except Exception as e:
                # this is one exception that should return a 'keep going' response
                if tornado_requests.is_refused(e):
                    numtries+=1
                    maxr = config.getint('tenant','max_retries')
                    if numtries >= maxr:
                        logger.error("Quitting after max number of retries to connect to %s"%(self.cloudnode_ip))
                        raise e
                    retry  = config.getfloat('tenant','retry_interval')
                    logger.info("Connection to %s refused %d/%d times, trying again in %f seconds..."%(self.cloudnode_ip,numtries,maxr,retry))
                    time.sleep(retry)
                    continue
                else:
                    raise e
                
            response_body = response.json()
            if response.status_code == 200:
                if "results" not in response_body or 'hmac' not in response_body['results']:
                    logger.critical("Error: unexpected http response body from Cloud Node: %s"%str(response.status_code))
                    break
                mac = response_body['results']['hmac']
                ex_mac = crypto.do_hmac(self.K,challenge)
                if mac == ex_mac:
                    logger.info("Key derivation successful")
                else:
                    logger.error("Key derivation failed")
            else:
                logger.error("Status command response: %d Unexpected response from Cloud Node."%response.status_code)
                common.log_http_response(logger,logging.ERROR,response_body)
                break
            break;

def main(argv=sys.argv):    
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('-c', '---command',action='store',dest='command',default='add',help="valid commands are add,delete,status,reactivate. defaults to add")
    parser.add_argument('-t', '--targethost',action='store',dest='node_ip',help="the IP address of the host to provision")
    parser.add_argument('-v', '--cv',action='store',dest='verifier_ip',help="the IP address of the cloud verifier")
    parser.add_argument('-u', '--uuid',action='store',dest='node_uuid',help="UUID for the node to provision")
    parser.add_argument('-f', '--file', action='store',default=None,help='Deliver the specified plaintext to the provisioned node')
    parser.add_argument('--cert',action='store',dest='ca_dir',default=None,help='Create and deliver a certificate using a CA created by ca-util. Pass in the CA directory or use "default" to use the standard dir')
    parser.add_argument('-k', '--key',action='store',dest='keyfile',help='an intermedia key file produced by user_data_encrypt')
    parser.add_argument('-p', '--payload', action='store',default=None,help='Specify the encrypted payload to deliver with encrypted keys specified by -k')
    parser.add_argument('--include',action='store',dest='incl_dir',default=None,help="Include additional files in provided directory in certificate zip file.  Must be specified with --cert")
    parser.add_argument('--whitelist',action='store',dest='ima_whitelist',default=None,help="Specify the location of an IMA whitelist")
    parser.add_argument('--exclude',action='store',dest='ima_exclude',default=None,help="Specify the location of an IMA exclude list")
    parser.add_argument('--tpm_policy',action='store',dest='tpm_policy',default=None,help="Specify a TPM policy in JSON format. e.g., {\"15\":\"0000000000000000000000000000000000000000\"}")
    parser.add_argument('--vtpm_policy',action='store',dest='vtpm_policy',default=None,help="Specify a vTPM policy in JSON format")

    if common.DEVELOP_IN_ECLIPSE:
        ca_util.setpassword('default')
        #tmp = ['-c','add','-t','127.0.0.1','-v', '127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9','-p','content_payload.txt','-k','content_keys.txt']
        #tmp = ['-c','add','-t','127.0.0.1','-v','127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9','-f','tenant.py']
        tmp = ['-c','add','-t','127.0.0.1','-v','127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9','--cert','ca/','--include','extras']
        #tmp = ['-c','delete','-t','127.0.0.1','-v','127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9']
        #tmp = ['-c','reactivate','-t','127.0.0.1','-v','127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9']
        #tmp = ['-c','list','-v', '127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9']
    else:
        tmp = argv[1:]

    args = parser.parse_args(tmp)
    
    mytenant = Tenant()
    
    if args.command != 'list' and args.node_ip is None:
        logger.error("-t/--targethost is required for command %s"%args.command)
    
    if args.node_uuid is not None:
        mytenant.node_uuid = args.node_uuid
        # if the uuid is actually a public key, then hash it
        if mytenant.node_uuid.startswith('-----BEGIN PUBLIC KEY-----'):
            mytenant.node_uuid = hashlib.sha256(mytenant.node_uuid).hexdigest()
    else:
        logger.warning("Using default UUID D432FBB3-D2F1-4A97-9EF7-75BD81C00000")
        mytenant.node_uuid = "D432FBB3-D2F1-4A97-9EF7-75BD81C00000"
    
    if args.verifier_ip is not None:  
        mytenant.cloudverifier_ip = args.verifier_ip
    
    try:
        if args.command=='add':
            mytenant.init_add(vars(args))
            mytenant.preloop()
            mytenant.do_cv()
            mytenant.do_quote()
            if common.DEVELOP_IN_ECLIPSE:
                time.sleep(2)
                mytenant.do_cvstatus()
                time.sleep(1)
                mytenant.do_verify()
                time.sleep(1)
                #invalidate it eventually
                logger.debug("invalidating PCR 15, forcing revocation")
                tpm_exec.run("extend -ix 15 -if tenant.py")
                time.sleep(5)
                logger.debug("Deleting node from verifier")
                mytenant.do_cvdelete()
        elif args.command=='delete':
            mytenant.do_cvdelete()
        elif args.command=='status':
            mytenant.do_cvstatus()
        elif args.command=='list':
            mytenant.do_cvstatus(listing=True)
        elif args.command=='reactivate':
            mytenant.do_cvreactivate()
        else:
            logger.error("Invalid command specified %s"%(args.command))
            sys.exit(2)
    except Exception as e:
        logger.error(traceback.print_exc())
        logger.error("Error: %s "%str(e))
    
if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)