#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.

Tools for creating a CA cert and signed server certs.
Divined from http://svn.osafoundation.org/m2crypto/trunk/tests/test_x509.py
The mk_temporary_xxx calls return a NamedTemporaryFile with certs.
Usage ;
   # Create a temporary CA cert and it's private key
   cacert, cakey = mk_temporary_cacert()
   # Create a temporary server cert+key, signed by the CA
   server_cert = mk_temporary_cert(cacert.name, cakey.name, '*.server.co.uk')

protips
# openssl verify -CAfile cacert.crt cacert.crt cert.crt
# openssl x509 -in cert.crt -noout -text
# openssl x509 -in cacert.crt -noout -text
'''

import sys
import os
import base64
import argparse
import datetime
import getpass
import glob
import zipfile
import io
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import time
import yaml
try:
    from yaml import CSafeLoader as SafeLoader, CSafeDumper as SafeDumper
except ImportError:
    from yaml import SafeLoader, SafeDumper

from cryptography import exceptions as crypto_exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from keylime import cmd_exec
from keylime import config
from keylime import crypto
from keylime import fs_util
from keylime import json
from keylime import revocation_notifier
from keylime import keylime_logging


logger = keylime_logging.init_logging('ca-util')

if config.CA_IMPL == 'cfssl':
    from keylime import ca_impl_cfssl as ca_impl
elif config.CA_IMPL == 'openssl':
    from keylime import ca_impl_openssl as ca_impl
else:
    raise Exception(f"Unknown CA implementation: {config.CA_IMPL}")



global_password = None

def load_cert_by_path(cert_path):
    cert = None
    with open(cert_path, 'rb') as ca_file:
        cert = x509.load_pem_x509_certificate(
            data=ca_file.read(),
            backend=default_backend(),
        )
    return cert

def setpassword(pw):
    global global_password
    if len(pw) == 0:
        raise Exception("You must specify a password!")
    global_password = pw


def cmd_mkcert(workingdir, name):
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        priv = read_private()
        cacert = load_cert_by_path('cacert.crt')
        ca_pk = serialization.load_pem_private_key(
            priv[0]['ca'],
            password=None,
            backend=default_backend()
        )

        cert, pk = ca_impl.mk_signed_cert(
            cacert, ca_pk, name, priv[0]['lastserial'] + 1)

        with open(f'{name}-cert.crt', 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        priv[0][name] = pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # increment serial number after successful creation
        priv[0]['lastserial'] += 1

        write_private(priv)

        with os.fdopen(os.open(f"{name}-private.pem", os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as f:
            f.write(priv[0][name])

        with os.fdopen(os.open(f"{name}-public.pem", os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as f:
            f.write(pk.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        cc = load_cert_by_path(f'{name}-cert.crt')
        pubkey = cacert.public_key()
        pubkey.verify(
            cc.signature,
            cc.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cc.signature_hash_algorithm,
        )

        logger.info("Created certificate for name %s successfully in %s", name, workingdir)
    except crypto_exceptions.InvalidSignature:
        logger.error("ERROR: Cert does not validate against CA")
    finally:
        os.chdir(cwd)


def cmd_init(workingdir):
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)

        rmfiles("*.pem")
        rmfiles("*.crt")
        rmfiles("*.zip")
        rmfiles("*.der")
        rmfiles("private.yml")

        cacert, ca_pk, _ = ca_impl.mk_cacert()  # pylint: disable=W0632
        priv = read_private()

        # write out keys
        with open('cacert.crt', 'wb') as f:
            f.write(cacert.public_bytes(serialization.Encoding.PEM))

        priv[0]['ca'] = ca_pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # store the last serial number created.
        # the CA is always serial # 1
        priv[0]['lastserial'] = 1

        write_private(priv)

        with os.fdopen(os.open("ca-public.pem", os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as f:
            f.write(ca_pk.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # generate an empty crl
        cacert_str = cacert.public_bytes(serialization.Encoding.PEM).decode()
        crl = ca_impl.gencrl([], cacert_str, priv[0]['ca'].decode())

        if isinstance(crl, str):
            crl = crl.encode('utf-8')

        with open('cacrl.der', 'wb') as f:
            f.write(crl)
        convert_crl_to_pem("cacrl.der", "cacrl.pem")

        # Sanity checks...
        cac = load_cert_by_path('cacert.crt')
        pubkey = cacert.public_key()
        pubkey.verify(
            cac.signature,
            cac.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cac.signature_hash_algorithm,
        )

        logger.info("CA certificate created successfully in %s", workingdir)
    except crypto_exceptions.InvalidSignature:
        logger.error("ERROR: Cert does not self validate")
    finally:
        os.chdir(cwd)


def cmd_certpkg(workingdir, name, insecure=False):
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        # zip up the crt, private key, and public key

        with open('cacert.crt', 'rb') as f:
            cacert = f.read()

        with open(f"{name}-public.pem", 'rb') as f:
            pub = f.read()

        with open(f"{name}-cert.crt", 'rb') as f:
            cert = f.read()

        with open('cacrl.der', 'rb') as f:
            crl = f.read()

        with open('cacrl.pem', 'rb') as f:
            crlpem = f.read()

        cert_obj = x509.load_pem_x509_certificate(
            data=cert,
            backend=default_backend(),
        )

        serial = cert_obj.serial_number
        subject = cert_obj.subject.rfc4514_string()

        priv = read_private()
        private = priv[0][name]

        with open(f"{name}-private.pem", 'rb') as f:
            prot_priv = f.read()

        # no compression to avoid extraction errors in tmpfs
        sf = io.BytesIO()
        with zipfile.ZipFile(sf, 'w', compression=zipfile.ZIP_STORED) as f:
            f.writestr(f"{name}-public.pem", pub)
            f.writestr(f"{name}-cert.crt", cert)
            f.writestr(f"{name}-private.pem", private)
            f.writestr('cacert.crt', cacert)
            f.writestr('cacrl.der', crl)
            f.writestr('cacrl.pem', crlpem)
        pkg = sf.getvalue()

        if insecure:
            logger.warning(
                "Unprotected private keys in cert package being written to disk")
            with open(f'{name}-pkg.zip', 'wb') as f:
                f.write(pkg)
        else:
            # actually output the package to disk with a protected private key
            with zipfile.ZipFile(f'{name}-pkg.zip', 'w', compression=zipfile.ZIP_STORED) as f:
                f.writestr(f"{name}-public.pem", pub)
                f.writestr(f"{name}-cert.crt", cert)
                f.writestr(f"{name}-private.pem", prot_priv)
                f.writestr('cacert.crt', cacert)
                f.writestr('cacrl.der', crl)
                f.writestr('cacrl.pem', crlpem)

        logger.info("Creating cert package for %s in %s-pkg.zip",
                    name, name)

        return pkg, serial, subject
    finally:
        os.chdir(cwd)


def convert_crl_to_pem(derfile, pemfile):
    if config.get('general', 'ca_implementation') == 'openssl':
        with open(pemfile, 'w', encoding="utf-8") as f:
            f.write("")
    else:
        cmd = ('openssl', 'crl', '-in', derfile, '-inform', 'der',
               '-out', pemfile)
        cmd_exec.run(cmd)


def get_crl_distpoint(cert_path):
    cert_obj = load_cert_by_path(cert_path)

    try:
        crl_distpoints = cert_obj.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for dstpnt in crl_distpoints:
            for point in dstpnt.full_name:
                if isinstance(point, x509.general_name.UniformResourceIdentifier):
                    return point.value

    except x509.extensions.ExtensionNotFound:
        pass
    logger.info("No CRL distribution points in %s", cert_path)
    return ""

# to check: openssl crl -inform DER -text -noout -in cacrl.der


def cmd_revoke(workingdir, name=None, serial=None):
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        priv = read_private()

        if name is not None and serial is not None:
            raise Exception(
                "You may not specify a cert and a serial at the same time")
        if name is None and serial is None:
            raise Exception("You must specify a cert or a serial to revoke")
        if name is not None:
            # load up the cert
            cert = load_cert_by_path(f'{name}-cert.crt')
            serial = cert.serial_number

        # convert serial to string
        serial = str(serial)

        # get the ca key cert and keys as strings
        with open('cacert.crt', encoding="utf-8") as f:
            cacert = f.read()
        ca_pk = priv[0]['ca'].decode('utf-8')

        if serial not in priv[0]['revoked_keys']:
            priv[0]['revoked_keys'].append(serial)

        crl = ca_impl.gencrl(priv[0]['revoked_keys'], cacert, ca_pk)

        write_private(priv)

        # write out the CRL to the disk
        if os.stat('cacrl.der').st_size:
            with open('cacrl.der', 'wb') as f:
                f.write(crl)
            convert_crl_to_pem("cacrl.der", "cacrl.pem")

    finally:
        os.chdir(cwd)
    return crl

# regenerate the crl without revoking anything


def cmd_regencrl(workingdir):
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        priv = read_private()

        # get the ca key cert and keys as strings
        with open('cacert.crt', encoding="utf-8") as f:
            cacert = f.read()
        ca_pk = priv[0]['ca'].decode()

        crl = ca_impl.gencrl(priv[0]['revoked_keys'], cacert, ca_pk)

        write_private(priv)

        # write out the CRL to the disk
        with open('cacrl.der', 'wb') as f:
            f.write(crl)
        convert_crl_to_pem("cacrl.der", "cacrl.pem")

    finally:
        os.chdir(cwd)
    return crl


def cmd_listen(workingdir, cert_path):
    cwd = os.getcwd()
    try:
        fs_util.ch_dir(workingdir)
        # just load up the password for later
        read_private(True)

        serveraddr = ('', config.CRL_PORT)
        server = ThreadedCRLServer(serveraddr, CRLHandler)
        if os.path.exists('cacrl.der'):
            logger.info("Loading existing crl: %s",
                        os.path.abspath("cacrl.der"))
            with open('cacrl.der', 'rb') as f:
                server.setcrl(f.read())
        t = threading.Thread(target=server.serve_forever)
        logger.info("Hosting CRL on %s:%d",
                    socket.getfqdn(), config.CRL_PORT)
        t.start()

        def check_expiration():
            logger.info("checking CRL for expiration every hour")
            while True:  # pylint: disable=R1702
                try:
                    if (os.path.exists('cacrl.der') and
                            os.stat('cacrl.der').st_size):
                        cmd = ('openssl', 'crl', '-inform', 'der', '-in',
                               'cacrl.der', '-text', '-noout')
                        retout = cmd_exec.run(cmd)['retout']
                        for line in retout:
                            line = line.strip()
                            if line.startswith(b"Next Update:"):
                                expire = datetime.datetime.strptime(
                                    line[13:].decode('utf-8'), "%b %d %H:%M:%S %Y %Z")
                                # check expiration within 6 hours
                                in1hour = datetime.datetime.utcnow() + datetime.timedelta(hours=6)
                                if expire <= in1hour:
                                    logger.info(
                                        "Certificate to expire soon %s, re-issuing", expire)
                                    cmd_regencrl(workingdir)
                    # check a little less than every hour
                    time.sleep(3540)

                except KeyboardInterrupt:
                    logger.info("TERM Signal received, shutting down...")
                    # server.shutdown()
                    break

        t2 = threading.Thread(target=check_expiration)
        t2.setDaemon(True)
        t2.start()

        def revoke_callback(revocation):
            json_meta = json.loads(revocation['meta_data'])
            serial = json_meta['cert_serial']
            if revocation.get('type', None) != 'revocation' or serial is None:
                logger.error("Unsupported revocation message: %s", revocation)
                return

            logger.info("Revoking certificate: %s", serial)
            server.setcrl(cmd_revoke(workingdir, None, serial))
        try:
            while True:
                try:
                    revocation_notifier.await_notifications(
                        revoke_callback, revocation_cert_path=cert_path)
                except Exception as e:
                    logger.exception(e)
                    logger.warning(
                        "No connection to revocation server, retrying in 10s...")
                    time.sleep(10)
        except KeyboardInterrupt:
            logger.info("TERM Signal received, shutting down...")
            server.shutdown()
            sys.exit()
    finally:
        os.chdir(cwd)


class ThreadedCRLServer(ThreadingMixIn, HTTPServer):
    published_crl = None

    def setcrl(self, crl):
        self.published_crl = crl


class CRLHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logger.info('GET invoked from %s with uri: %s', str(self.client_address), self.path)

        if self.server.published_crl is None:
            self.send_response(404)
            self.end_headers()
        else:
            # send back the CRL
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.server.published_crl)


def rmfiles(path):
    files = glob.glob(path)
    for f in files:
        os.remove(f)


def write_private(inp):
    priv = inp[0]
    salt = inp[1]

    priv_encoded = yaml.dump(priv, Dumper=SafeDumper)
    key = crypto.kdf(global_password, salt)
    ciphertext = crypto.encrypt(priv_encoded, key)
    towrite = {'salt': salt, 'priv': ciphertext}

    with os.fdopen(os.open('private.yml', os.O_WRONLY | os.O_CREAT, 0o600), 'w', encoding="utf-8") as f:
        yaml.dump(towrite, f, Dumper=SafeDumper)


def read_private(warn=False):
    if global_password is None:
        setpassword(getpass.getpass(
            "Please enter the password to decrypt your keystore: "))

    if os.path.exists('private.yml'):
        with open('private.yml', encoding="utf-8") as f:
            toread = yaml.load(f, Loader=SafeLoader)
        key = crypto.kdf(global_password, toread['salt'])
        try:
            plain = crypto.decrypt(toread['priv'], key)
        except ValueError as e:
            raise Exception("Invalid password for keystore") from e

        return yaml.load(plain, Loader=SafeLoader), toread['salt']

    if warn:
        # file doesn't exist, just invent a salt
        logger.warning("Private certificate data %s does not exist yet.",
                       os.path.abspath("private.yml"))
        logger.warning(
            "Keylime will attempt to load private certificate data again when it is needed.")
    return {'revoked_keys': []}, base64.b64encode(crypto.generate_random_key()).decode()


def main(argv=sys.argv):  #pylint: disable=dangerous-default-value
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('-c', '--command', action='store', dest='command',
                        required=True, help="valid commands are init,create,pkg,revoke,listen")
    parser.add_argument('-n', '--name', action='store',
                        help='the common name of the certificate to create')
    parser.add_argument('-d', '--dir', action='store',
                        help='use a custom directory to store certificates and keys')
    parser.add_argument('-i', '--insecure', action='store_true', default=False,
                        help='create cert packages with unprotected private keys and write them to disk.  USE WITH CAUTION!')

    args = parser.parse_args(argv[1:])

    if args.dir is None:
        if not os.access(config.WORK_DIR, os.R_OK + os.W_OK):
            logger.error(
                "If you don't specify a working directory, this process must be run as a user with access to %s",
                config.WORK_DIR)
            sys.exit(-1)
        workingdir = config.CA_WORK_DIR
    else:
        workingdir = args.dir

    # set a conservative general umask
    os.umask(0o077)

    if args.command == 'init':
        cmd_init(workingdir)
    elif args.command == 'create':
        if args.name is None:
            logger.error(
                "you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_mkcert(workingdir, args.name)
    elif args.command == 'pkg':
        if args.name is None:
            logger.error(
                "you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_certpkg(workingdir, args.name, args.insecure)
    elif args.command == 'revoke':
        if args.name is None:
            logger.error(
                "you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_revoke(workingdir, args.name)
    elif args.command == 'listen':
        if args.name is None:
            args.name = os.path.join(workingdir, 'RevocationNotifier-cert.crt')
            logger.warning("using default name for revocation cert %s",
                           args.name)
        cmd_listen(workingdir, args.name)
    else:
        logger.error("Invalid command: %s", args.command)
        parser.print_help()
        sys.exit(-1)
