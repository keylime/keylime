#!/usr/bin/env python

'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for 
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the 
Assistant Secretary of Defense for Research and Engineering.

Copyright 2017 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
above. Use of this work other than as specifically authorized by the U.S. Government may 
violate any copyrights that exist in this work.
'''

import zmq
import common
import ConfigParser
import json
import crypto
import threading
import functools
import time
import os
import sys

logger = common.init_logging('revocation_notifier')

config = ConfigParser.SafeConfigParser()
config.read(common.CONFIG_FILE)

global_socket = None

def start_broker():
    global global_socket
    context = zmq.Context()
    global_socket = context.socket(zmq.PUB)
    global_socket.bind("tcp://*:%s"%config.getint('general','revocation_notifier_port'))
    
def stop_broker():
    global global_socket
    global_socket.close()

def notify(tosend):
    def worker(tosend):
        global global_socket
        # now send it out vi 0mq non blocking
        for i in range(config.getint('cloud_verifier','max_retries')):
            try:
                global_socket.send(json.dumps(tosend))
                break
            except Exception as _:
                logger.debug("Unable to publish revocation message %d times, trying again in %f seconds"%(i,config.getfloat('cloud_verifier','retry_interval')))
                time.sleep(config.getfloat('cloud_verifier','retry_interval'))
    
    cb = functools.partial(worker,tosend)
    t = threading.Thread(target=cb)
    t.start()
         

cert_key=None

def await_notifications(callback,revocation_cert_path):
    global cert_key
    
    if revocation_cert_path is None:
        raise Exception("must specify revocation_cert_path")
    
    context = zmq.Context()
    mysock = context.socket(zmq.SUB)
    mysock.setsockopt(zmq.SUBSCRIBE, '')
    
    mysock.connect("tcp://%s:%s"%(config.get('general','revocation_notifier_ip'),config.getint('general','revocation_notifier_port')))
    
    logger.info('Waiting for revocation messages on 0mq %s:%s'%
                (config.get('general','revocation_notifier_ip'),config.getint('general','revocation_notifier_port')))
    
    while True:
        rawbody = mysock.recv()
        
        body = json.loads(rawbody)
        if cert_key is None:
            # load up the CV signing public key
            if revocation_cert_path is not None and os.path.exists(revocation_cert_path):
                logger.info("Lazy loading the revocation certificate from %s"%revocation_cert_path)
                with open(revocation_cert_path,'r') as f:
                    certpem = f.read()
                cert_key = crypto.rsa_import_pubkey(certpem)
        
        if cert_key is None:
            logger.warning("Unable to check signature of revocation message: %s not available"%revocation_cert_path)
        elif str(body['signature'])=='none':
            logger.warning("No signature on revocation message from server")
        elif not crypto.rsa_verify(cert_key,str(body['revocation']),str(body['signature'])):
            logger.error("Invalid revocation message siganture %s"%body)
        else:
            revocation = json.loads(body['revocation'])
            logger.debug("Revocation signature validated for revocation: %s"%revocation)
            callback(revocation)

def main():
    start_broker()
    
    import secure_mount
    
    def worker():
        def print_notification(revocation):
            logger.warning("Received revocation: %s"%revocation)
            
        keypath = '%s/unzipped/RevocationNotifier-cert.crt'%(secure_mount.mount())
        await_notifications(print_notification,revocation_cert_path=keypath)
    
    t = threading.Thread(target=worker)
    t.start()
    time.sleep(0.5)

    json_body2 = {
        'v': 'vbaby',
        'instance_id': '2094aqrea3',
        'cloudnode_ip': 'ipaddy',
        'cloudnode_port': '39843',
        'tpm_policy': '{"ab":"1"}',
        'vtpm_policy': '{"ab":"1"}',
        'metadata': '{"cert_serial":"1"}',
        'ima_whitelist': '{}',
        'revocation_key': '',
        'revocation': '{"cert_serial":"1"}',
        }
    
    print "sending notification"
    notify(json_body2)
    
    time.sleep(2)
    print "shutting down"
    stop_broker()
    sys.exit(0)
     
if __name__=="__main__":
    main()
