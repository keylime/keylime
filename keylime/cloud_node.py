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

import common
logger = common.init_logging('cloudnode')


import BaseHTTPServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
from urlparse import urlparse
import json
import base64
import ConfigParser
import uuid
import crypto
import os
import sys
import tpm_quote
import tpm_initialize
import registrar_client
import tpm_nvram
import secure_mount
import signal
import time
import hashlib
import openstack
import zipfile
import cStringIO

# read the config file
config = ConfigParser.RawConfigParser()
config.read(common.CONFIG_FILE)

#lock required for multithreaded operation
uvLock = threading.Lock()

class Handler(BaseHTTPRequestHandler):
    parsed_path = '' 
    
    def do_HEAD(self):
        """Not supported.  Will always return a 400 response"""
        self.do_GET()

    def do_GET(self):
        """This method services the GET request typically from either the Tenant or the Cloud Verifier.
        
        Only tenant and cloudverifier uri's are supported. Both requests require a nonce parameter.  
        The Cloud verifier requires an additional mask paramter.  If the uri or parameters are incorrect, a 400 response is returned.
        """
        
        logger.info('GET invoked from ' + str(self.client_address)  + ' with uri:' + self.path)
        
        if not self.is_quote():
            logger.warning('GET returning 400 response. uri not supported: ' + self.path)
            self.send_response(400)
            self.end_headers()
            return
         
        nonce = self.get_query_tag_value(self.path, 'nonce')
        pcrmask = self.get_query_tag_value(self.path, 'mask')
        vpcrmask = self.get_query_tag_value(self.path, 'vmask')
          
        # if the query is not messed up
        if nonce is None:
            logger.warning('GET quote returning 400 response. nonce not provided as an HTTP parameter in request')
            self.send_response(400)
            self.end_headers()
            return 
        
        if self.is_tenant_quote():
            #always need share when talking to the tenant
            need_share = True
        elif self.is_cloudverifier_quote():
            # if we already have a K, then no need to ask for V again
            if self.server.K is not None and self.get_query_tag_value(self.path, 'need_pubkey') !='True':
                need_share = False   
            else:
                need_share = True                      
        else:
            logger.warning('GET returning 400 response. uri not supported: ' + self.path)
            self.send_response(400)
            self.end_headers()
            return  
        
        if vpcrmask is None:
            quote = tpm_quote.create_quote(nonce, self.server.rsapublickey_exportable,pcrmask)
            imaMask = pcrmask
        else:
            quote = tpm_quote.create_deep_quote(nonce, self.server.rsapublickey_exportable, vpcrmask, pcrmask)
            imaMask = vpcrmask
            
        response = { 'quote': quote }

        if need_share:
            response['pubkey'] = self.server.rsapublickey_exportable
            
        # return a measurement list if available
        if tpm_quote.check_mask(imaMask, common.IMA_PCR):
            if not os.path.exists(common.IMA_ML):
                logger.warn("IMA measurement list not available: %s"%(common.IMA_ML))
            else:
                with open(common.IMA_ML,'r') as f:
                    ml = f.read()
                response['ima_measurement_list']=ml
             
        json_response = json.dumps(response)  
           
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json_response)
        logger.info('GET %s quote returning 200 response.'%('tenant','verifier')[self.is_cloudverifier_quote()])
        return

    def do_POST(self):
        """This method services the GET request typically from either the Tenant or the Cloud Verifier.
        
        Only tenant and cloudverifier uri's are supported. Both requests require a nonce parameter.  
        The Cloud verifier requires an additional mask parameter.  If the uri or parameters are incorrect, a 400 response is returned.
        """        
        tn_quote_flag = self.is_tenant_quote()
        cv_quote_flag = self.is_cloudverifier_quote()
        if tn_quote_flag or cv_quote_flag: 
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_body = self.rfile.read(content_length)
                json_body = json.loads(post_body)
                    
                b64_encrypted_key = json_body['encrypted_key']
                decrypted_key = crypto.rsa_decrypt(self.server.rsaprivatekey,base64.b64decode(b64_encrypted_key))
                
                have_derived_key = False

                if tn_quote_flag:                                                                                                                         
                    self.server.add_U(decrypted_key)
                    self.server.auth_tag = json_body['auth_tag']
                    self.server.payload = json_body.get('payload',None)
                    
                    have_derived_key = self.server.attempt_decryption(self)
                elif cv_quote_flag:                                                                                                                                
                    self.server.add_V(decrypted_key)
                    have_derived_key = self.server.attempt_decryption(self)
                else:
                    logger.warning('POST returning  response. uri not supported: ' + self.path)
                    self.send_response(400)
                    self.end_headers()
                    return
                logger.info('POST of %s key returning 200'%(('V','U')[tn_quote_flag]))
                self.send_response(200)
                self.end_headers()
                
                if have_derived_key: 
                    # ok lets write out the key now
                    secdir = secure_mount.mount() # confirm that storage is still securely mounted
                    
                    f = open(secdir+"/"+self.server.enc_keyname,'w')
                    f.write(base64.b64encode(self.server.K))
                    f.close()
                    
                    # if we have a good key, now attempt to write out the encrypted payload
                    dec_path = "%s/%s"%(secdir, config.get('cloud_node',"dec_payload_file"))
                    enc_path = "%s/encrypted_payload"%common.WORK_DIR
                    if self.server.payload is not None:
                        plaintext = crypto.decrypt(self.server.payload, str(self.server.K))
                        zfio = cStringIO.StringIO(plaintext)
                        
                        if config.getboolean('cloud_node','extract_payload_zip') and zipfile.is_zipfile(zfio):
                            logger.info("Decrypting and unzipping payload to %s/unzipped"%dec_path)
                            with zipfile.ZipFile(zfio,'r')as f:
                                f.extractall('%s/unzipped'%secdir)
                        else:
                            logger.info("Decrypting payload to %s"%dec_path)
                            with open(dec_path,'w') as f:
                                f.write(plaintext)
                        zfio.close()
                        
                        # also write out encrypted payload to be decrytped next time
                        with open(enc_path,'w') as f:
                            f.write(self.server.payload)
                            
                    elif os.path.exists(enc_path):
                        # if no payload provided, try to decrypt one from a previous run stored in encrypted_payload                       
                        with open(enc_path,'r') as f:
                            payload = f.read()
                        try:
                            with open(dec_path,'w') as fp:
                                fp.write(crypto.decrypt(payload,str(self.server.K)))
                                logger.info("Decrypted previous payload in %s to %s"%(enc_path,dec_path))
                        except Exception as e:
                            logger.warning("Unable to decrypt previous payload %s with derived key: %s"%(enc_path,e))
                            os.remove(enc_path)
                        
                    #stow the U value for later
                    tpm_nvram.write_key_nvram(self.server.final_U)
                    
                    return                   
            else:
                logger.warning('POST returning 400 response, expected content in message. url:  ' + self.path)
                self.send_response(400)
                self.end_headers()
                return     
        else:
            logger.warning('POST returning 400 response. uri not supported: ' + self.path)
            self.send_response(400)
            self.end_headers()
            return      
    
    def is_quote(self):
        """Returns True if this is  quote uri, else False"""  
        parsed_path = urlparse(self.path.strip("/"))
        tokens = parsed_path.path.split('/')
        return len(tokens) >= 2 and tokens[0] == 'v1' and tokens[1] == 'quotes' 
    
    def is_tenant_quote(self):
        """Returns True if this is a tenant quote uri, else False"""  
        parsed_path = urlparse(self.path.strip("/"))
        tokens = parsed_path.path.split('/')
        return len(tokens) == 3 and tokens[0] == 'v1' and tokens[1] == 'quotes' and tokens[2] == 'tenant'

    def is_cloudverifier_quote(self):
        """Returns True if this is a cloud verifier quote uri, else False"""  
        parsed_path = urlparse(self.path.strip("/"))
        tokens = parsed_path.path.split('/')
        return len(tokens) == 3 and tokens[0] == 'v1' and tokens[1] == 'quotes' and tokens[2] == 'cloudverifier'

    def get_query_tag_value(self, path, query_tag):
        """This is a utility method to query for specific the http parameters in the uri.  
        
        Returns the value of the parameter, or None if not found."""  
        data = { }
        parsed_path = urlparse(self.path)
        query_tokens = parsed_path.query.split('&')
        # find the 'ids' query, there can only be one
        for tok in query_tokens:
            query_tok = tok.split('=')
            query_key = query_tok[0]
            if query_key is not None and query_key == query_tag:
                # ids tag contains a comma delimited list of ids
                data[query_tag] = query_tok[1]    
                break        
        return data.get(query_tag,None) 
    
    def log_message(self, logformat, *args):
        return
                
#consider using PooledProcessMixIn
# https://github.com/muayyad-alsadi/python-PooledProcessMixIn
class CloudNodeHTTPServer(ThreadingMixIn, HTTPServer):
    """Http Server which will handle each request in a separate thread."""

    instances = {}
    client_id = uuid.uuid4()

    cloudnode_port = None
   
    ''' Do not modify directly unless you acquire uvLock. Set chosen for uniqueness of contained values''' 
    u_set = set([])
    v_set = set([])
    
    rsaprivatekey = None
    rsapublickey = None
    rsapublickey_exportable = None
    done = threading.Event()
    auth_tag = None
    payload = None
    enc_keyname = None
    K = None
    final_U = None
    node_uuid = None
    
    def __init__(self, server_address, RequestHandlerClass, node_uuid):
        """Constructor overridden to provide ability to pass configuration arguments to the server"""
        keyname = config.get('cloud_node','rsa_keyname')
        
        # read or generate the key depending on configuration
        if os.path.isfile(keyname):
            # read in private key
            logger.debug( "Using existing key in %s"%keyname)
            f = open(keyname,"r")
            rsa_key = crypto.rsa_import_privkey(f.read())
        else:
            logger.debug("key not found, generating a new one")
            rsa_key = crypto.rsa_generate(2048)
            f = open(keyname,"w")
            f.write(crypto.rsa_export_privkey(rsa_key))
            f.close()
        
        self.rsaprivatekey = rsa_key
        self.rsapublickey_exportable = crypto.rsa_export_pubkey(self.rsaprivatekey)
        
        #attempt to get a U value from the TPM NVRAM
        nvram_u = tpm_nvram.read_key_nvram()
        if nvram_u is not None:
            logger.info("Existing U loaded from TPM NVRAM")
            self.add_U(nvram_u)
        BaseHTTPServer.HTTPServer.__init__(self, server_address, RequestHandlerClass)
        self.enc_keyname = config.get('cloud_node','enc_keyname')
        self.node_uuid = node_uuid


    def add_U(self, u):
        """Threadsafe method for adding a U value received from the Tenant
        
        Do not modify u_set of v_set directly.
        """
        with uvLock:
            # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
            if common.DEVELOP_IN_ECLIPSE:
                logger.debug( "Adding U len %d data:%s"%(len(u),base64.b64encode(u)))
            self.u_set.add(u)

        
    def add_V(self, v):
        """Threadsafe method for adding a U value received from the Cloud Verifier
        
        Do not modify u_set of v_set directly.        
        """
        with uvLock:
            # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
            if common.DEVELOP_IN_ECLIPSE:
                logger.debug( "Adding V: " + base64.b64encode(v))
            self.v_set.add(v)

    def attempt_decryption(self, handler):
        """On reception of a U or V value, this method is called to attempt the decryption of the Cloud Init script
        
        At least one U and V value must be received in order to attempt encryption. Multiple U and V values are stored
        to prevent an attacker from sending U/V values to deny service.  
        """
        with uvLock:
            both_u_and_v_present = False
            return_value = False
            for u in self.u_set:
                for v in self.v_set:
                    both_u_and_v_present = True
                    return_value = self.decrypt_check(u,v)
                    if return_value:
                        return return_value
            #TODO check on whether this happens or not.  NVRAM causes trouble
            if both_u_and_v_present: 
                pass
                #logger.critical("Possible attack from: " + str(handler.client_address) + ".  Both U (potentially stale from TPM NVRAM) and V present but unsuccessful in attempt to decrypt check value.")
            return return_value
            
    def decrypt_check(self, decrypted_U, decrypted_V):    
        """Decrypt the Cloud init script with the passed U and V values.
        
        This method will access the received auth tag, and may fail if decoy U and V values were received.
        Do not call directly unless you acquire uvLock. Returns None if decryption unsuccessful, else returns the 
        decrypted node UUID.
        """
        if self.auth_tag is None:
            return None
        
        if len(decrypted_U) != len(decrypted_V):
            logger.warning("Invalid U len %d or V len %d. skipping..."%(len(decrypted_U),len(decrypted_V)))
            return None
        
        self.K = crypto.strbitxor(decrypted_U, decrypted_V)
        
        # be very careful printing K, U, or V as they leak in logs stored on unprotected disks
        if common.DEVELOP_IN_ECLIPSE:
            logger.debug("U: " + base64.b64encode(decrypted_U))
            logger.debug("V: " + base64.b64encode(decrypted_V))
            logger.debug("K: " + base64.b64encode(self.K))
            
        logger.debug( "auth_tag: " + self.auth_tag)
        ex_mac = crypto.do_hmac(str(self.K),self.node_uuid)
        
        if ex_mac == self.auth_tag:
            logger.info( "Successfully derived K for UUID %s",self.node_uuid)
            self.final_U = decrypted_U
            return True

        return False
    
def do_shutdown(servers):
        for server in servers:
            server.shutdown()
                        
def main(argv=sys.argv):
    if os.getuid()!=0 and not common.DEVELOP_IN_ECLIPSE:
        logger.critical("This process must be run as root.")
        return

    # get params for initialization
    registrar_ip = config.get('general', 'registrar_ip')
    registrar_port = config.get('general', 'registrar_port')
    
    # initialize the tmpfs partition to store keys if it isn't already available
    secure_mount.mount()

    # change dir to working dir
    common.ch_dir()
    
    #initialize tpm 
    (ek,ekcert,aik) = tpm_initialize.init(self_activate=False,config_pw=config.get('cloud_node','tpm_ownerpassword')) # this tells initialize not to self activate the AIK
    virtual_node = tpm_initialize.is_vtpm()
    
    if common.STUB_TPM:
        ekcert = common.TEST_EK_CERT
        
    if virtual_node and (ekcert is None or common.STUB_TPM):
        ekcert = 'virtual'
        
    # now we need the UUID
    try:
        node_uuid = config.get('cloud_node','node_uuid')
    except ConfigParser.NoOptionError:
        node_uuid = None
    if node_uuid == 'openstack':
        node_uuid = openstack.get_openstack_uuid()
    elif node_uuid == 'hash_ek':
        node_uuid = hashlib.sha256(ek).hexdigest()
    elif node_uuid == 'generate' or node_uuid is None:
        node_uuid = str(uuid.uuid4())
    if common.DEVELOP_IN_ECLIPSE:
        node_uuid = "C432FBB3-D2F1-4A97-9EF7-75BD81C866E9"

    # use an TLS context with no certificate checking 
    registrar_client.noAuthTLSContext(config)
        
    # register it and get back a blob
    keyblob = registrar_client.doRegisterNode(registrar_ip,registrar_port,node_uuid,ek,ekcert,aik)
    
    if keyblob is None:
        raise Exception("Registration failed")
    
    # get the ephemeral registrar key
    key = tpm_initialize.activate_identity(keyblob)
    
    # tell the registrar server we know the key
    if virtual_node:
        deepquote = tpm_quote.create_deep_quote(hashlib.sha1(key).hexdigest(),node_uuid+aik+ek)
        registrar_client.doActivateVirtualNode(registrar_ip, registrar_port, node_uuid, deepquote)
    else:
        registrar_client.doActivateNode(registrar_ip,registrar_port,node_uuid,key)

    serveraddr = ('', config.getint('general', 'cloudnode_port'))
    server = CloudNodeHTTPServer(serveraddr, Handler,node_uuid)

    thread = threading.Thread(target=server.serve_forever)

    threads = []
    servers = []

    threads.append(thread)
    servers.append(server)
    
    # start the server
    logger.info( 'Starting Cloud Node on port %s use <Ctrl-C> to stop'%serveraddr[1])
    for thread in threads:
        thread.start()
    
    def signal_handler(signal, frame):
        do_shutdown(servers)
        sys.exit(0)   

    # Catch these signals.  Note that a SIGKILL cannot be caught, so
    # killing this process with "kill -9" may result in improper shutdown 
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)


    # keep the main thread active, so it can process the signals and gracefully shutdown    
    while True:
        if not any([thread.isAlive() for thread in threads]):
            # All threads have stopped
            break
        else:
            # Some threads are still going
            time.sleep(1)

    for thread in threads:
        thread.join()

    
if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)

