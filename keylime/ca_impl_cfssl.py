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

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from keylime import config
from keylime import json
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
            logger.info("Connection to cfssl refused %d/%d times, trying again in %f seconds...",
                        numtries, maxr, retry)
            time.sleep(retry)
            continue

    if response.status_code != 200:
        raise Exception(f"Unable to issue CFSSL API command {params}: {response.text}")
    return response.json()


def start_cfssl(cmdline=""):
    if shutil.which("cfssl") is None:
        logger.error(
            "cfssl binary not found in the path.  Please install cfssl or change the setting \"ca_implementation\" in keylime.conf")
        sys.exit(1)
    global cfsslproc
    cmd = f"cfssl serve -loglevel=1 {cmdline} "
    env = os.environ.copy()
    env['PATH'] = env['PATH'] + ":/usr/local/bin"

    # make sure cfssl isn't running
    os.system('pkill -x cfssl')

    cfsslproc = subprocess.Popen(cmd, env=env, shell=True, stdout=subprocess.PIPE,  #pylint: disable=consider-using-with
                                 stderr=subprocess.STDOUT, universal_newlines=True)
    if cfsslproc.returncode is not None:
        raise Exception(f"Unable to launch {cmd}: failed with code {cfsslproc.returncode}")

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
        cfsslproc.communicate()
        os.system("pkill -x cfssl")
        cfsslproc = None


def mk_cacert(name=None):
    """
    Make a CA certificate.
    Returns the certificate, private key and public key.
    """

    if name is None:
        name = config.get("ca", "cert_ca_name")

    csr = {"CN": name,
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
        privkey = serialization.load_pem_private_key(
            body['result']['private_key'].encode('utf-8'),
            password=None,
            backend=default_backend(),
        )
        cert = x509.load_pem_x509_certificate(
            data=body['result']['certificate'].encode('utf-8'),
            backend=default_backend(),
        )
        return cert, privkey, cert.public_key()

    raise Exception("Unable to create CA")


def mk_signed_cert(cacert, ca_pk, name, serialnum):
    del serialnum
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
        # to tmpfs.
        with os.fdopen(os.open(f"{secdir}/ca-key.pem", os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as f:
            f.write(ca_pk.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
                )
            )

        with open(os.path.join(secdir, 'cfsslconfig.yml'), 'w', encoding="utf-8") as f:
            json.dump(cfsslconfig, f)

        with open(f"{secdir}/cacert.crt", 'wb') as f:
            f.write(cacert.public_bytes(serialization.Encoding.PEM))

        cmdline = f"-config={secdir}/cfsslconfig.yml"

        privkey_path = os.path.abspath(f"{secdir}/ca-key.pem")
        cacert_path = os.path.abspath(f"{secdir}/cacert.crt")

        cmdline += f" -ca-key {privkey_path} -ca {cacert_path}"

        start_cfssl(cmdline)
        body = post_cfssl('api/v1/cfssl/newcert', csr)
    finally:
        stop_cfssl()
        os.remove(os.path.join(secdir, "ca-key.pem"))
        os.remove(os.path.join(secdir, "cfsslconfig.yml"))
        os.remove(os.path.join(secdir, "cacert.crt"))

    if body['success']:
        pk = serialization.load_pem_private_key(
            body['result']['private_key'].encode('utf-8'),
            password=None,
            backend=default_backend(),
        )
        cert = x509.load_pem_x509_certificate(
            data=body['result']['certificate'].encode('utf-8'),
            backend=default_backend(),
        )
        return cert, pk

    raise Exception(f"Unable to create cert for {name}")


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
        privkey_path = os.path.abspath(f"{secdir}/ca-key.pem")
        with open(privkey_path, 'w', encoding="utf-8") as f:
            f.write(ca_pk)

        cacert_path = os.path.abspath(f"{secdir}/cacert.crt")
        with open(cacert_path, 'w', encoding="utf-8") as f:
            f.write(cert)

        cmdline = f" -ca-key {privkey_path} -ca {cacert_path}"

        start_cfssl(cmdline)
        body = post_cfssl('api/v1/cfssl/gencrl', request)

    finally:
        stop_cfssl()
        # replace with srm
        os.remove(privkey_path)
        os.remove(cacert_path)


    if body['success']:
        retval = base64.b64decode(body['result'])
    else:
        raise Exception(f"Unable to create crl for cert serials {serials}. "
                        f"Error: {body['errors']}")
    return retval
    # ./cfssl gencrl revoke ca.pem ca-key.pem | base64 -D > mycrl.der

# mk_cacert()
# mk_signed_cert("", "", "hello", None)
