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
logger = common.init_logging('registrar-common')

import BaseHTTPServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from urlparse import urlparse
import json
import threading
import traceback
import sys
import tpm_initialize
import crypto
import base64
import ConfigParser
import registrar_client
import tpm_quote
import signal
import time
import hashlib
import cloud_verifier_common
import ssl
import sqlite3
import os

config = ConfigParser.SafeConfigParser()
config.read(common.CONFIG_FILE)
      
class RegistrarHandler(BaseHTTPRequestHandler):

    def is_instance_resource(self):
        """Returns True if this is an instance_id uri, else False"""  
        parsed_path = urlparse(self.path.strip("/"))
        tokens = parsed_path.path.split('/')
        return len(tokens) == 3 and tokens[0] == 'v1' and tokens[1] == 'instance_id'

    def get_resource_name(self):
        """Returns returns the resource_id of an instance_id uri, or None if error"""  
        parsed_path = urlparse(self.path.strip("/"))
        tokens = parsed_path.path.split('/')
        if len(tokens) == 3 and tokens[0] == 'v1' and tokens[1] == 'instance_id':
            return tokens[2]
        else:
            return None

    def do_HEAD(self):
        """HEAD not supported"""    
        self.send_response(204)
        self.end_headers()
        return
    
    def do_POST(self):
        """POST not supported"""         
        self.send_response(403)
        self.end_headers()
        return
    
    def do_PATCH(self):
        """POST not supported"""      
        self.send_response(403)
        self.end_headers()
        return  
       
    def do_GET(self):
        """This method handles the GET requests to retrieve status on instances from the Registrar Server. 
        
        Currently, only instances resources are available for GETing, i.e. /v1/instances. All other GET uri's 
        will return errors. instances requests require a single instance_id parameter which identifies the 
        instance to be returned. If the instance_id is not found, a 404 response is returned.
        """
        if not self.is_instance_resource(): 
            self.send_response(400)
            self.end_headers()
            logger.warning('GET returning 400 response. uri not supported: ' + self.path)
            return  
        
        parsed_path = urlparse(self.path.strip("/"))
        tokens = parsed_path.path.split('/')
        instance_id = tokens[2]
                                                                                                                                                        
        instance = self.server.find_instance(instance_id)
        
        if instance is None:
            self.send_response(404)
            self.end_headers()
            logger.warning('GET returning 404 response. instance_id ' + instance_id + ' not found.')  
            return      
        
        if not instance['active']:
            self.send_response(404)
            self.end_headers()
            logger.warning('GET returning 404 response. instance_id ' + instance_id + ' not yet active.')  
            return      
        
        response = {
            'aik': instance['aik']
        }
        
        json_response = json.dumps(response)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json_response)  
        logger.info('GET returning 200 response for instance_id:' + instance_id)
        return

           
    def do_PUT(self):
        """This method handles the POST requests to add instances to the Registrar Server. 
        
        Currently, only instances resources are available for POSTing, i.e. /v1/instances. All other POST uri's 
        will return errors. PUT requests require an an instance_id identifying the instance to add, and json 
        block sent in the body with 2 entries: ek and aik.  
        """
        if not self.is_instance_resource():
            self.send_response(400)
            self.end_headers()
            logger.warning('PUT instance returning 400 response. uri not supported: ' + self.path)
            return
        
        instance_id = self.get_resource_name()
        
        if instance_id is None:
            self.send_response(400)
            self.end_headers()
            logger.warning('PUT instance returning 400 response. instance_id not found in uri ' + self.path)
            return                   

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_response(400)
                self.end_headers()
                logger.warning('PUT for ' + instance_id + ' returning 400 response. Expected non zero content length.')
                return 
        
            post_body = self.rfile.read(content_length)
            json_body = json.loads(post_body)
            
            command = json_body['command']
            
            if command=='register_node':
                ek = json_body['ek']
                ekcert = json_body['ekcert']
                aik = json_body['aik']
                
                # config option must be on to check for EK certs
                if config.getboolean('registrar','require_ek_cert'):
                    # no EK provided
                    if ekcert is None and not common.DEVELOP_IN_ECLIPSE:
                        raise Exception("No EK cert provided, require_ek_cert option in config set to True")
                    
                    # there is an EK
                    if not common.STUB_TPM and (ekcert!=None and ekcert!='virtual' and not tpm_initialize.verify_ek(base64.b64decode(ekcert), ek)):
                            raise Exception("Invalid EK certificate")
                
                # try to encrypt the AIK
                (blob,key) = tpm_initialize.encryptAIK(instance_id,aik,ek)
                self.server.add_instance(instance_id, key, aik,ek,ekcert)
                response = {
                        'blob': blob,
                }
                json_response = json.dumps(response)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json_response)
                
                logger.info('PUT returning key blob for instance_id: ' + instance_id)
                return
            elif command=='activate_node':
                auth_tag=json_body['auth_tag']
                
                instance = self.server.find_instance(instance_id)
                if instance is None:
                    raise Exception("attempting to activate instance before requesting registrar for %s"%instance_id)
         
                if instance['virtual']:
                    raise Exception("attempting to activate virtual AIK using physical interface for %s"%instance_id)
                
                if common.STUB_TPM:
                    self.server.update_instance(instance_id, 'active',True)
                else:
                    ex_mac = crypto.do_hmac(base64.b64decode(instance['key']),instance_id)
                    if ex_mac == auth_tag:
                        self.server.update_instance(instance_id, 'active',True)
                    else:
                        raise Exception("Auth tag %s does not match expected value %s"%(auth_tag,ex_mac))
                
                self.send_response(200)
                self.end_headers()
                logger.info('PUT activated: ' + instance_id)      
            elif command=='activate_virtual_node':
                deepquote = json_body.get('deepquote',None)

                instance = self.server.find_instance(instance_id)
                if instance is None:
                    raise Exception("attempting to activate instance before requesting registrar for %s"%instance_id)
                      
                if not instance['virtual']:
                    raise Exception("attempting to activate physical AIK using virtual interface for %s"%instance_id)
                
                # get an physical AIK for this host
                registrar_client.serverAuthTLSContext(config, 'registrar')
                dq_aik = registrar_client.getAIK(config.get('general', 'provider_registrar_ip'), config.get('general', 'provider_registrar_port'), instance_id)
                # we already have the vaik
                if not tpm_quote.check_deep_quote(hashlib.sha1(instance['key']),
                                                  instance_id+instance['aik']+instance['ek'], 
                                                  deepquote,  
                                                  instance['aik'],  
                                                  dq_aik):
                    raise Exception("Deep quote invalid")
                
                self.server.update_instance(instance_id, 'active',True)
                
                self.send_response(200)
                self.end_headers()
                logger.info('PUT activated: ' + instance_id)           
            else:
                pass           
        except Exception as e:
            self.send_response(400)
            self.end_headers()
            logger.warning("PUT for " + instance_id + " returning 400 response. Error: %s"%e)
            logger.warning(traceback.format_exc())
            return
            

    def do_DELETE(self):
        """This method handles the DELETE requests to remove instances from the Registrar Server. 
        
        Currently, only instances resources are available for DELETEing, i.e. /v1/instances. All other DELETE uri's will return errors.
        instances requests require a single instance_id parameter which identifies the instance to be deleted.    
        """
        if self.is_instance_resource():
            instance_id = self.get_resource_name()
            
            if instance_id is not None:
                if self.server.remove_instance(self.get_resource_name()):
                    #send response
                    self.send_response(200)        
                    self.end_headers()
                    return
                else:
                    #send response
                    self.send_response(404)        
                    self.end_headers()
                    return             
            else:
                self.send_response(404)        
                self.end_headers()
                return                    
        else:
            self.send_response(400)        
            self.end_headers()            
            return
    def log_message(self, logformat, *args):
        return  

               
#consider using PooledProcessMixIn
# https://github.com/muayyad-alsadi/python-PooledProcessMixIn
class ThreadedRegistrarServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    instances = {}
    db_filename = None
    
    def __init__(self, server_address, dbname,RequestHandlerClass):
        """Constructor overridden to provide ability to read file"""
        
        self.db_filename = "%s/%s"%(common.WORK_DIR,dbname)
        
        self.init_db()
        
        count = self.count_instances()
        if count>0:
            logger.info("Loaded %d public keys from database"%count)
    
        #some DB testing stuff
#         self.add_instance('3948320948', 'mykey', 'myaik', 'myek', 'ekcerty')
#         self.update_instance('3948320948','key','newkey')
#         print self.remove_instance('3948320948')
#         self.add_instance('3948320948', 'mykey', 'myaik', 'myek', 'ekcerty')
#         print self.find_instance('3948320948')
#         sys.exit(0)
          
        BaseHTTPServer.HTTPServer.__init__(self, server_address, RequestHandlerClass)

    def shutdown(self):
        BaseHTTPServer.HTTPServer.shutdown(self)
        
        
    def init_db(self):
        os.umask(0o077)
        kl_dir = os.path.dirname(os.path.abspath(self.db_filename))
        if not os.path.exists(kl_dir):
            os.makedirs(kl_dir, 0o700)
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS main(instance_id TEXT PRIMARY_KEY, key TEXT, aik TEXT, ek TEXT, ekcert TEXT, virtual INT, active INT)")
            conn.commit()
        os.chmod(self.db_filename,0o600)
    def print_db(self):
        return
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM main')
            rows = cur.fetchall()

            colnames = [description[0] for description in cur.description]
            print colnames
            for row in rows:
                print row
                
    def add_instance(self, instance_id, key, aik, ek,ekcert):
        """Threadsafe function to add an instance to the instances container."""
        # always overwrite instances with same ID
        self.remove_instance(instance_id)
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('INSERT INTO main VALUES(?,?,?,?,?,?,?)',(instance_id,key,aik,ek,ekcert,int(ekcert=='virtual'),int(False)))
            conn.commit()
            
        self.print_db()
    
    def remove_instance(self, instance_id):
        """Threadsafe function to remove an instance to the instances container."""
        if self.find_instance(instance_id) is None:
            return False
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('DELETE FROM main WHERE instance_id=?',(instance_id,))
            conn.commit()
        
        self.print_db()
        return True
        
    def update_instance(self, instance_id, key, value):
        """Threadsafe function to query the existance of an instance in the instances container. Returns None 
        on failure, else the CloudInstance object"""
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('UPDATE main SET %s = ? where instance_id = ?'%(key),(value,instance_id))
            conn.commit()
        
        self.print_db()
                   
    def find_instance(self, instance_id):
        """Threadsafe function to query the existance of an instance in the instances container. Returns None 
        on failure, else the CloudInstance object"""   
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT * from main where instance_id=?',(instance_id,))
            rows = cur.fetchall()
            if len(rows)==0:
                return None
            
            colnames = [description[0] for description in cur.description]
            d ={}
            for i in range(len(colnames)):
                d[colnames[i]]=rows[0][i]
            return d
        
    def count_instances(self):
        with sqlite3.connect(self.db_filename) as conn:
            cur = conn.cursor()
            cur.execute('SELECT instance_id from main')
            rows = cur.fetchall()
            return len(rows)

def do_shutdown(servers):
        for server in servers:
            server.shutdown()

def start(port,dbfile):
    """Main method of the Registrar Server.  This method is encapsulated in a function for packaging to allow it to be 
    called as a function by an external program."""
    
    #take in a port on the command line
    if port is not None:
        registrar_port = port 
    else:
        registrar_port = config.getint('general', 'registrar_port')
        
    serveraddr = ('', registrar_port)
    server = ThreadedRegistrarServer(serveraddr, dbfile, RegistrarHandler)    
    context = cloud_verifier_common.init_tls(config,
                                             section='registrar',
                                             verifymode=ssl.CERT_OPTIONAL,
                                             generatedir='reg_ca',
                                             need_client=False)
    if context is not None:
        server.socket = context.wrap_socket (server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever)

    threads = []
    servers = []

    threads.append(thread)
    servers.append(server)
    
    logger.info('Starting Cloud Registrar Server on port %s use <Ctrl-C> to stop'%serveraddr[1])
    logger.info('Require EK certificates: %s'%config.getboolean('registrar','require_ek_cert'))
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



