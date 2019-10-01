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

import configparser
import threading
import functools
import time
import os
import sys
import signal
import zmq
try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

from multiprocessing import Process

from keylime import common
from keylime import keylime_logging
from keylime import crypto

logger = keylime_logging.init_logging('revocation_notifier')

config = configparser.ConfigParser()
config.read(common.CONFIG_FILE)

broker_proc = None

def start_broker():
    def worker():
        context = zmq.Context(1)
        frontend = context.socket(zmq.SUB)
        frontend.bind("ipc:///tmp/keylime.verifier.ipc")

        frontend.setsockopt(zmq.SUBSCRIBE, b'')

        # Socket facing services
        backend = context.socket(zmq.PUB)
        backend.bind("tcp://*:%s"%config.getint('general','revocation_notifier_port'))

        zmq.device(zmq.FORWARDER, frontend, backend)

    global broker_proc
    broker_proc = Process(target=worker)
    broker_proc.start()


def stop_broker():
    global broker_proc
    if broker_proc is not None:
        os.kill(broker_proc.pid,signal.SIGKILL)

def notify(tosend):
    def worker(tosend):
        context = zmq.Context()
        mysock = context.socket(zmq.PUB)
        mysock.connect("ipc:///tmp/keylime.verifier.ipc")
        # wait 100ms for connect to happen
        time.sleep(0.1)
        # now send it out vi 0mq
        for i in range(config.getint('cloud_verifier','max_retries')):
            try:
                mysock.send_string(json.dumps(tosend))
                break
            except Exception as e:
                logger.debug("Unable to publish revocation message %d times, trying again in %f seconds: %s"%(i,config.getfloat('cloud_verifier','retry_interval'),e))
                time.sleep(config.getfloat('cloud_verifier','retry_interval'))
        mysock.close()

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
    mysock.setsockopt(zmq.SUBSCRIBE, b'')
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
        elif 'signature' not in body or body['signature']=='none':
            logger.warning("No signature on revocation message from server")
        elif not crypto.rsa_verify(cert_key,body['msg'].encode('utf-8'),body['signature'].encode('utf-8')):
            logger.error("Invalid revocation message siganture %s"%body)
        else:
            message = json.loads(body['msg'])
            logger.debug("Revocation signature validated for revocation: %s"%message)
            callback(message)

def main():
    start_broker()

    from keylime import secure_mount

    def worker():
        def print_notification(revocation):
            logger.warning("Received revocation: %s"%revocation)

        keypath = '%s/unzipped/RevocationNotifier-cert.crt'%(secure_mount.mount())
        await_notifications(print_notification,revocation_cert_path=keypath)

    t = threading.Thread(target=worker)
    t.start()
    #time.sleep(0.5)

    json_body2 = {
        'v': 'vbaby',
        'agent_id': '2094aqrea3',
        'cloudagent_ip': 'ipaddy',
        'cloudagent_port': '39843',
        'tpm_policy': '{"ab":"1"}',
        'vtpm_policy': '{"ab":"1"}',
        'metadata': '{"cert_serial":"1"}',
        'ima_whitelist': '{}',
        'revocation_key': '',
        'revocation': '{"cert_serial":"1"}',
        }

    print("sending notification")
    notify(json_body2)

    time.sleep(2)
    print("shutting down")
    stop_broker()
    print("exiting...")
    sys.exit(0)
    print("done")

if __name__=="__main__":
    main()
