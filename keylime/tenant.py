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
import cloud_verifier_common

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

    uuid_service_generate_locally = None
    node_uuid = None
    
    K = None
    V = None
    U = None
    auth_tag = None
    
    tpm_policy = None
    vtpm_policy = None
    
    payload = None
    
    context = None
    
    def readPolicy(self,configval):
        policy = json.loads(configval)
        
        # compute PCR mask from tpm_policy
        mask = 0
        for key in policy.keys():
            if not key.isdigit() or int(key)>24:
                raise Exception("Invalid tpm policy pcr number: %s"%(key))
            
            if int(key)==common.TPM_DATA_PCR:
                raise Exception("Invalid whitelist PCR number %s, keylime uses this PCR to bind data."%key)
            mask = mask + (1<<int(key))
            
            # wrap it in a list if it is a singleton
            if isinstance(policy[key],basestring):
                policy[key]=[policy[key]]
                
        policy['mask'] = "0x%X"%(mask)
        return policy
    
    def __init__(self, vtpm):
        self.cloudverifier_port = config.get('general', 'cloudverifier_port')
        self.cloudnode_port = config.get('general', 'cloudnode_port')
        self.registrar_port = config.get('general', 'registrar_port')
        
        self.cloudverifier_ip = config.get('tenant', 'cloudverifier_ip')
        self.registrar_ip = config.get('tenant', 'cloudverifier_ip')
        
        if config.getboolean('general',"enable_tls"):
            ca_cert = config.get('tenant', 'ca_cert')
            my_cert = config.get('tenant', 'my_cert')
            my_priv_key = config.get('tenant', 'private_key')
            my_key_pw = config.get('tenant','private_key_pw')
            
            tls_dir = config.get('tenant','tls_dir')
            
            if tls_dir == 'default':
                ca_cert = 'cacert.crt'
                my_cert = 'tenant-cert.crt'
                my_priv_key = 'tenant-private.pem'
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
        
            self.context = ssl.create_default_context()
            self.context.load_verify_locations(cafile=ca_path)   
            self.context.load_cert_chain(certfile=my_cert,keyfile=my_priv_key,password=my_key_pw)
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.check_hostname = config.getboolean('general','tls_check_hostnames')
        else:
            logger.warning("TLS is currently disabled, keys will be sent in the clear! Should only be used for testing")
            self.context = None
        
        
        self.tpm_policy = self.readPolicy(config.get('tenant', 'tpm_policy'))
        logger.info("TPM PCR Mask from policy is %s"%self.tpm_policy['mask'])

        #optional arg for vtpm policy for virtual nodes
        if vtpm:
            self.vtpm_policy = self.readPolicy(config.get('tenant', 'vtpm_policy'))
            logger.info("vTPM PCR Mask from policy is %s"%self.vtpm_policy['mask'])
        else:
            self.vtpm_policy ={}
    
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
        registrar_client.serverAuthTLSContext(config,'tenant')
        aikFromRegistrar = registrar_client.getAIK(self.cloudverifier_ip,self.registrar_port,self.node_uuid)
        if aikFromRegistrar is not None:
            return tpm_quote.check_quote(self.nonce,public_key,quote,aikFromRegistrar)
        else:
            logger.warning("AIK not found in registrar, quote not validated")
            return False


    def do_cv(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        b64_v = base64.b64encode(self.V)
        logger.debug("b64_v:" + b64_v)
        data = {
            'v': b64_v,
            'instance_id': self.node_uuid,
            'cloudnode_ip': self.cloudnode_ip,
            'cloudnode_port': self.cloudnode_port,
            'tpm_policy': json.dumps(self.tpm_policy),
            'vtpm_policy': json.dumps(self.vtpm_policy),
            }
                    
        json_message = json.dumps(data)
        response = tornado_requests.request("POST","http://%s:%s/v1/instances"%(self.cloudverifier_ip,self.cloudverifier_port),data=json_message,context=self.context)
        if response.status_code != 200:
            raise Exception("POST command response: %d Unexpected response from Cloud Verifier: %s"%(response.status_code,response.body))
                                                                                                                        
                    
    def do_cvstatus(self,listing=False):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        params={}
        if not listing:
            params['instance_id']=self.node_uuid

        response = tornado_requests.request("GET", "http://%s:%s/v1/instances"%(self.cloudverifier_ip,self.cloudverifier_port),params=params,context=self.context)
        if response.status_code != 200:
            logger.error("Status command response: %d Unexpected response from Cloud Verifier."%response.status_code)
        else:
            logger.info("Node Status %d: %s"%(response.status_code,response.json()))

    def do_cvdelete(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        params = {
            'instance_id': self.node_uuid,
            }
        
        response = tornado_requests.request("DELETE","http://%s:%s/v1/instances"%(self.cloudverifier_ip,self.cloudverifier_port),params=params,context=self.context)
        if response.status_code != 200:
            logger.error("Delete command response: %d Unexpected response from Cloud Verifier."%response.status_code)
        else:
            logger.info("Node %s deleted from CV"%(self.node_uuid))
            
    def do_cvreactivate(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        params = {
            'instance_id': self.node_uuid,
            }
        data = {
            'operational_state':cloud_verifier_common.CloudInstance_Operational_State.START
            }
        response = tornado_requests.request("POST","http://%s:%s/v1/instances"%(self.cloudverifier_ip,self.cloudverifier_port),params=params,data=json.dumps(data),context=self.context)
        if response.status_code != 200:
            logger.error("Update command response: %d Unexpected response from Cloud Verifier."%response.status_code)
        else:
            logger.info("Node %s re-activated"%(self.node_uuid))
        
    def do_quote(self):
        """initiaite v, instance_id and ip
        initiate the cloudinit sequence"""
        self.nonce = tpm_initialize.random_password(20)
        
        params = {
            'nonce': self.nonce,
            }
        
        numtries = 0
        while True:
            try:
                response = tornado_requests.request("GET", 
                                            "http://%s:%s/v1/quotes/tenant"%(self.cloudnode_ip,self.cloudnode_port),
                                            params=params)
            except Exception as e:
                # this is one exception that should return a 'keep going' response
                if tornado_requests.is_refused(e):
                    numtries+=1
                    maxr = config.getint('tenant','max_retries')
                    if numtries >= maxr:
                        logger.error("Quiting after max number of retries to connect to %s"%(self.cloudnode_ip))
                        raise e
                    retry  = config.getfloat('tenant','retry_interval')
                    logger.info("Connection to %s refused %d/%d times, trying again in %f seconds..."%(self.cloudnode_ip,numtries,maxr,retry))
                    time.sleep(retry)
                    continue
                else:
                    raise e
                
            if response.status_code == 200:
                response_body = response.json()        
            
                public_key = response_body["pubkey"]
                logger.debug("cnquote received public key:" + public_key)
                quote = response_body["quote"]
                logger.debug("cnquote received quote:" + quote)
            
                if self.validate_tpm_quote(public_key, quote):
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
                    response = tornado_requests.request("POST", "http://%s:%s/v1/quotes/tenant"%(self.cloudnode_ip,self.cloudnode_port),data=u_json_message)
                    
                    if response.status_code != 200:
                        logger.error("Posting of Encrypted U to the Cloud Node failed with response code %d" %response.status_code)
                        break
                                       
                else:
                    logger.error("TPM Quote from cloud node is invalid for nonce: %s"%self.nonce)
                    break
            else:
                logger.error("Status command response: %d Unexpected response from Cloud Node."%response.status_code)
                break
            break;

def main(argv=sys.argv):    
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('-c', '---command',action='store',dest='command',default='add',help="valid commands are add,delete,status,reactivate. defaults to add")
    parser.add_argument('-t', '--targethost',action='store',dest='node_ip',help="the IP address of the host to provision")
    parser.add_argument('-v', '--cv',action='store',dest='verifier_ip',help="the IP address of the cloud verifier")
    parser.add_argument('-u', '--uuid',action='store',dest='node_uuid',help="UUID for the node to provision")
    parser.add_argument('-m', '--vtpm', action='store_true',default=False,help='Use to provision a system with a VTPM')
    parser.add_argument('-f', '--file', action='store',default=None,help='Deliver the specified plaintext to the provisioned node')
    parser.add_argument('--cert',action='store',dest='ca_dir',default=None,help='Create and deliver a certificate using a CA created by ca-util. Pass in the CA directory or use "default" to use the standard dir')
    parser.add_argument('-k', '--key',action='store',dest='keyfile',help='an intermedia key file produced by user_data_encrypt')
    parser.add_argument('-p', '--payload', action='store',default=None,help='Specify the encrypted payload to deliver with encrypted keys specified by -k')

    
    if common.DEVELOP_IN_ECLIPSE:
        #tmp = ['-c','add','-t','127.0.0.1','-v', '127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9','-p','content_payload.txt','-k','content_keys.txt']
        tmp = ['-c','add','-t','127.0.0.1','-v','127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9','-f','tenant.py']
        #tmp = ['-c','delete','-t','127.0.0.1','-v','127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9']
        #tmp = ['-c','reactivate','-t','127.0.0.1','-v','127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9']
        #tmp = ['-c','list','-v', '127.0.0.1','-u','C432FBB3-D2F1-4A97-9EF7-75BD81C866E9']
    else:
        tmp = argv[1:]

    args = parser.parse_args(tmp)
    
    mytenant = Tenant(args.vtpm)
    
    if args.command != 'list' and args.node_ip is None:
        logger.error("-t/--targethost is required for command %s"%args.command)
    
    if args.node_uuid is not None:
        mytenant.node_uuid = args.node_uuid
    else:
        logger.warning("Using default UUID D432FBB3-D2F1-4A97-9EF7-75BD81C00000")
        mytenant.node_uuid = "D432FBB3-D2F1-4A97-9EF7-75BD81C00000"
    
    if args.command == 'add':
        # command line options can overwrite config values
        mytenant.cloudnode_ip = args.node_ip
            
        # if none
        if (args.file is None and 
            args.keyfile is None and 
            args.ca_dir is None):
            logger.error("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
            sys.exit(2)

        if args.keyfile is not None:
            if args.file is not None or args.ca_dir is not None:
                logger.error("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
                sys.exit(2)
            
            # read the keys in
            f = open(args.keyfile,'r')
            mytenant.K = base64.b64decode(f.readline())
            mytenant.U = base64.b64decode(f.readline())
            mytenant.V = base64.b64decode(f.readline())
            f.close()
            
            if args.payload is not None:
                f = open(args.payload,'r')
                mytenant.payload = f.read()
                f.close() 
        
        if args.file is not None:
            if args.keyfile is not None or args.ca_dir is not None:
                logger.error("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
                sys.exit(2)
                
            with open(args.file,'r') as f:
                contents = f.read()
            ret = user_data_encrypt.encrypt(contents)
            mytenant.K = ret['k']
            mytenant.U = ret['u']
            mytenant.V = ret['v']
            mytenant.payload = ret['ciphertext']
            
        if args.ca_dir is not None:
            if args.file is not None or args.keyfile is not None:
                logger.error("You must specify one of -k, -f, or --cert to specify the key/contents to be securely delivered to the node")
                sys.exit(2)
            if args.ca_dir=='default':
                args.ca_dir = common.CA_WORK_DIR
            
            if not os.path.exists(args.ca_dir):
                logger.error("CA directory does not exist")
                sys.exit(2)
            
            print "Creating a certificate for %s in CA directory %s"%(mytenant.node_uuid,args.ca_dir)
            ca_util.cmd_mkcert(args.ca_dir,mytenant.node_uuid)
            contents = ca_util.cmd_certpkg(args.ca_dir,mytenant.node_uuid, needfile=False)
            ret = user_data_encrypt.encrypt(contents)
            mytenant.K = ret['k']
            mytenant.U = ret['u']
            mytenant.V = ret['v']
            mytenant.payload = ret['ciphertext']     
            
        if mytenant.payload is not None and len(mytenant.payload)>config.getint('tenant','max_payload_size'):
            raise Exception("Payload size %s exceeds max size %d"%(len(mytenant.payload),config.getint('tenant','max_payload_size'))) 
        
    if args.verifier_ip is not None:  
        mytenant.cloudverifier_ip = args.verifier_ip
    
    try:
        if args.command=='add':
            mytenant.preloop()
            mytenant.do_cv()
            mytenant.do_quote()
            if common.DEVELOP_IN_ECLIPSE:
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
        logger.error("Error getting info from cloud verifier: " + str(e))
    
if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
