'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import base64
import os
import subprocess
import socket
import time
import shutil
import sys

import requests
import simplejson as json
from M2Crypto import EVP, X509

from keylime import config
from keylime import keylime_logging
from keylime import secure_mount

logger = keylime_logging.init_logging('ca_impl_cfssl')

cfssl_ip = config.get('ca', 'cfssl_ip')
cfssl_port = config.get('ca', 'cfssl_port')

cfsslproc = None


def post_cfssl(params, data):
    numtries = 0
    maxr = 10
    retry = 0.2
    while True:
        try:
            response = requests.post(
                f"http://{cfssl_ip}:{cfssl_port}/{params}", json=data, timeout=1)
            break
        except requests.exceptions.ConnectionError as e:
            numtries += 1
            if numtries >= maxr:
                logger.error(
                    "Quiting after max number of retries to connect to cfssl server")
                raise e
            logger.info(
                "Connection to cfssl refused %d/%d times, trying again in %f seconds..." % (numtries, maxr, retry))
            time.sleep(retry)
            continue

    if response.status_code != 200:
        raise Exception("Unable to issue CFSSL API command %s: %s" %
                        (params, response.text))
    return response.json()


def start_cfssl(cmdline=""):
    if shutil.which("cfssl") is None:
        logger.error(
            "cfssl binary not found in the path.  Please install cfssl or change the setting \"ca_implementation\" in keylime.conf")
        sys.exit(1)
    global cfsslproc
    cmd = "cfssl serve -loglevel=1 %s " % cmdline
    env = os.environ.copy()
    env['PATH'] = env['PATH'] + ":/usr/local/bin"

    # make sure cfssl isn't running
    os.system('pkill -f cfssl')

    cfsslproc = subprocess.Popen(cmd, env=env, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, universal_newlines=True)
    if cfsslproc.returncode is not None:
        raise Exception("Unable to launch %s: failed with code %d" %
                        (cmd, cfsslproc.returncode))

    logger.debug("Waiting for cfssl to start...")
    while True:
        line = cfsslproc.stdout.readline()
        if "Now listening on" in line:
            break
    time.sleep(0.2)  # give cfssl a little more time to get started
    logger.debug("cfssl started successfully")


def stop_cfssl():
    global cfsslproc
    if cfsslproc is not None:
        cfsslproc.kill()
        os.system("pkill -f cfssl")
        cfsslproc = None


def mk_cacert():
    csr = {"CN": config.get('ca', 'cert_ca_name'),
           "key": {
               "algo": "rsa",
               "size": config.getint('ca', 'cert_bits')
    },
        "names": [
               {
                   "C": config.get('ca', 'cert_country'),
                   "L": config.get('ca', 'cert_locality'),
                   "O": config.get('ca', 'cert_organization'),
                   "OU": config.get('ca', 'cert_org_unit'),
                   "ST": config.get('ca', 'cert_state')
               }
    ]
    }
    try:
        start_cfssl()
        body = post_cfssl('api/v1/cfssl/init_ca', csr)
    finally:
        stop_cfssl()

    if body['success']:
        pk_str = body['result']['private_key']
        pk = EVP.load_key_string(body['result']['private_key'].encode('utf-8'))
        cert = X509.load_cert_string(
            body['result']['certificate'].encode('utf-8'))
        pkey = cert.get_pubkey()

        return pk_str, cert, pk, pkey

    raise Exception("Unable to create CA")


def mk_signed_cert(cacert, ca_pk, name, serialnum):
    del cacert, serialnum
    csr = {"request": {
        "CN": name,
        "hosts": [
            name,
        ],
        "key": {
            "algo": "rsa",
            "size": config.getint('ca', 'cert_bits')
        },
        "names": [
            {
                "C": config.get('ca', 'cert_country'),
                "L": config.get('ca', 'cert_locality'),
                "O": config.get('ca', 'cert_organization'),
                "OU": config.get('ca', 'cert_org_unit'),
                "ST": config.get('ca', 'cert_state')
            }
        ]
    }
    }

    # check CRL distribution point
    disturl = config.get('ca', 'cert_crl_dist')
    if disturl == 'default':
        disturl = f"http://{socket.getfqdn()}:{config.CRL_PORT}/crl.der"

    # set up config for cfssl server
    cfsslconfig = {
        "signing": {
            "default": {
                "usages": ["client auth", "server auth", "key agreement", "key encipherment", "signing", "digital signature", "data encipherment"],
                "expiry": "8760h",
                "crl_url": disturl,
            }
        }
    }
    secdir = secure_mount.mount()
    try:
        # need to temporarily write out the private key with no password
        # to tmpfs
        ca_pk.save_key('%s/ca-key.pem' % secdir, None)
        with open(os.path.join(secdir, 'cfsslconfig.yml'), 'w', encoding="utf-8") as f:
            json.dump(cfsslconfig, f)

        cmdline = "-config=%s/cfsslconfig.yml" % secdir

        priv_key = os.path.abspath("%s/ca-key.pem" % secdir)
        cmdline += " -ca-key %s -ca cacert.crt" % (priv_key)

        start_cfssl(cmdline)
        body = post_cfssl('api/v1/cfssl/newcert', csr)
    finally:
        stop_cfssl()
        os.remove('%s/ca-key.pem' % secdir)
        os.remove('%s/cfsslconfig.yml' % secdir)

    if body['success']:
        pk = EVP.load_key_string(body['result']['private_key'].encode('utf-8'))
        cert = X509.load_cert_string(
            body['result']['certificate'].encode("utf-8"))
        return cert, pk

    raise Exception("Unable to create cert for %s" % name)


def gencrl(serials, cert, ca_pk):
    request = {"certificate": cert,
               "serialNumber": serials,
               "issuingKey": ca_pk,
               "expireTime": ""
               }
    secdir = secure_mount.mount()
    try:
        # need to temporarily write out the private key with no password
        # to tmpfs
        priv_key = os.path.abspath("%s/ca-key.pem" % secdir)
        with open(priv_key, 'w', encoding="utf-8") as f:
            f.write(ca_pk)
        cmdline = " -ca-key %s -ca cacert.crt" % (priv_key)

        start_cfssl(cmdline)
        body = post_cfssl('api/v1/cfssl/gencrl', request)

    finally:
        stop_cfssl()
        # replace with srm
        os.remove('%s/ca-key.pem' % secdir)

    if body['success']:
        retval = base64.b64decode(body['result'])
    else:
        raise Exception(f"Unable to create crl for cert serials {serials}. "
                        f"Error: {body['errors']}")
    return retval
    # ./cfssl gencrl revoke ca.pem ca-key.pem | base64 -D > mycrl.der

# mk_cacert()
# mk_signed_cert("", "", "hello", None)
