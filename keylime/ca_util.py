#!/usr/bin/python3

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

import sys
import os
import base64
import argparse
import configparser
import datetime
import getpass
import zipfile
import io
import socket
from keylime import revocation_notifier
import threading
import http.server
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import functools
import signal
import time
import yaml
try:
    from yaml import CSafeLoader as SafeLoader, CSafeDumper as SafeDumper
except ImportError:
    from yaml import SafeLoader as SafeLoader, SafeDumper as SafeDumper

from keylime import crypto
from keylime import cmd_exec
from keylime import common

from keylime import keylime_logging
logger = keylime_logging.init_logging('ca-util')

if common.CA_IMPL=='cfssl':
    from keylime import ca_impl_cfssl as ca_impl
elif common.CA_IMPL=='openssl':
    from keylime import ca_impl_openssl as ca_impl
else:
    raise Exception("Unknown CA implementation: %s"%common.CA_IMPL)
from M2Crypto import X509, EVP, BIO

config = configparser.ConfigParser()
config.read(common.CONFIG_FILE)

"""
Tools for creating a CA cert and signed server certs.
Divined from http://svn.osafoundation.org/m2crypto/trunk/tests/test_x509.py
The mk_temporary_xxx calls return a NamedTemporaryFile with certs.
Usage ;
   # Create a temporary CA cert and it's private key
   cacert, cakey = mk_temporary_cacert()
   # Create a temporary server cert+key, signed by the CA
   server_cert = mk_temporary_cert(cacert.name, cakey.name, '*.server.co.uk')
"""
# protips
# openssl verify -CAfile cacert.crt cacert.crt cert.crt
# openssl x509 -in cert.crt -noout -text
# openssl x509 -in cacert.crt -noout -text

global_password=None
def globalcb(*args):
    global global_password
    return global_password.encode()

def setpassword(pw):
    global global_password
    if len(pw)==0:
        raise Exception("You must specify a password!")
    global_password = pw

def cmd_mkcert(workingdir,name):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,logger)
        priv = read_private()
        cacert = X509.load_cert('cacert.crt')
        ca_pk = EVP.load_key_string(priv[0]['ca'])

        cert,pk = ca_impl.mk_signed_cert(cacert,ca_pk,name,priv[0]['lastserial']+1)

        with open('%s-cert.crt'%name, 'wb') as f:
            f.write(cert.as_pem())

        f = BIO.MemoryBuffer()
        pk.save_key_bio(f,None)
        priv[0][name]=f.getvalue()
        f.close()

        #increment serial number after successful creation
        priv[0]['lastserial']+=1

        write_private(priv)

        # write out the private key with password
        with os.fdopen(os.open("%s-private.pem"%name,os.O_WRONLY | os.O_CREAT,0o600), 'wb') as f:
            biofile = BIO.File(f)
            pk.save_key_bio(biofile, 'aes_256_cbc', globalcb)
            biofile.close()

        pk.get_rsa().save_pub_key('%s-public.pem'%name)

        cc = X509.load_cert('%s-cert.crt'%name)

        if cc.verify(cacert.get_pubkey()):
            logger.info("Created certificate for name %s successfully in %s"%(name,workingdir))
        else:
            logger.error("ERROR: Cert does not validate against CA")
    finally:
        os.chdir(cwd)

def cmd_init(workingdir):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,logger)

        rmfiles("*.pem")
        rmfiles("*.crt")
        rmfiles("*.zip")
        rmfiles("*.der")
        rmfiles("private.yml")

        if common.CA_IMPL=='cfssl':
            pk_str, cacert, ca_pk, _ = ca_impl.mk_cacert()
        elif common.CA_IMPL=='openssl':
            cacert, ca_pk, _ = ca_impl.mk_cacert()
        else:
            raise Exception("Unknown CA implementation: %s"%common.CA_IMPL)

        priv=read_private()

        # write out keys
        with open('cacert.crt', 'wb') as f:
            f.write(cacert.as_pem())

        f = BIO.MemoryBuffer()
        ca_pk.save_key_bio(f,None)
        priv[0]['ca']=f.getvalue()
        f.close()

        # store the last serial number created.
        # the CA is always serial # 1
        priv[0]['lastserial'] = 1

        write_private(priv)

        ca_pk.get_rsa().save_pub_key('ca-public.pem')

        # generate an empty crl
        if common.CA_IMPL=='cfssl':
            crl = ca_impl.gencrl([],cacert.as_pem(), pk_str)
        elif common.CA_IMPL=='openssl':
            crl = ca_impl.gencrl([],cacert.as_pem(),str(priv[0]['ca']))
        else:
            raise Exception("Unknown CA implementation: %s"%common.CA_IMPL)

        if isinstance(crl, str):
            crl = crl.encode('utf-8')

        with open('cacrl.der','wb') as f:
            f.write(crl)
        convert_crl_to_pem("cacrl.der","cacrl.pem")

        # Sanity checks...
        cac = X509.load_cert('cacert.crt')
        if cac.verify():
            logger.info("CA certificate created successfully in %s"%workingdir)
        else:
            logger.error("ERROR: Cert does not self validate")
    finally:
        os.chdir(cwd)

def cmd_certpkg(workingdir,name,insecure=False):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,logger)
        # zip up the crt, private key, and public key

        with open('cacert.crt','r') as f:
            cacert = f.read()

        with open("%s-public.pem"%name,'r') as f:
            pub = f.read()

        with open("%s-cert.crt"%name,'r') as f:
            cert = f.read()

        with open('cacrl.der','rb') as f:
            crl = f.read()

        with open('cacrl.pem','r') as f:
            crlpem = f.read()

        cert_obj = X509.load_cert_string(cert)
        serial = cert_obj.get_serial_number()
        subject = str(cert_obj.get_subject())

        priv = read_private()
        private = priv[0][name]

        with open("%s-private.pem"%name,'r') as f:
            prot_priv = f.read()

        #code to create a pem formatted protected private key using the keystore password
    #     pk = EVP.load_key_string(str(priv[0][name]))
    #     f = BIO.MemoryBuffer()
    #     # globalcb will return the global password provided by the user
    #     pk.save_key_bio(f, 'aes_256_cbc', globalcb)
    #     prot_priv = f.getvalue()
    #     f.close()

        # no compression to avoid extraction errors in tmpfs
        sf = io.BytesIO()
        with zipfile.ZipFile(sf,'w',compression=zipfile.ZIP_STORED) as f:
            f.writestr('%s-public.pem'%name,pub)
            f.writestr('%s-cert.crt'%name,cert)
            f.writestr('%s-private.pem'%name,private)
            f.writestr('cacert.crt',cacert)
            f.writestr('cacrl.der',crl)
            f.writestr('cacrl.pem',crlpem)
        pkg = sf.getvalue()

        if insecure:
            logger.warn("Unprotected private keys in cert package being written to disk")
            with open('%s-pkg.zip'%name,'w') as f:
                f.write(pkg)
        else:
            # actually output the package to disk with a protected private key
            with zipfile.ZipFile('%s-pkg.zip'%name,'w',compression=zipfile.ZIP_STORED) as f:
                f.writestr('%s-public.pem'%name,pub)
                f.writestr('%s-cert.crt'%name,cert)
                f.writestr('%s-private.pem'%name,prot_priv)
                f.writestr('cacert.crt',cacert)
                f.writestr('cacrl.der',crl)
                f.writestr('cacrl.pem',crlpem)

        logger.info("Creating cert package for %s in %s-pkg.zip"%(name,name))

        return pkg,serial,subject
    finally:
        os.chdir(cwd)

def convert_crl_to_pem(derfile,pemfile):
    if config.get('general','ca_implementation')=='openssl':
        with open(pemfile,'w') as f:
            f.write("")
    else:
        cmd_exec.run("openssl crl -in %s -inform der -out %s"%(derfile,pemfile),lock=False)

def get_crl_distpoint(cert_path):
    cert_obj = X509.load_cert(cert_path)
    text= cert_obj.as_text()
    incrl=False
    distpoint=""
    for line in text.split('\n'):
        line = line.strip()
        if line.startswith("X509v3 CRL Distribution Points:"):
            incrl = True
        if incrl and line.startswith("URI:"):
            distpoint = line[4:]
            break

    return distpoint

# to check: openssl crl -inform DER -text -noout -in cacrl.der
def cmd_revoke(workingdir,name=None,serial=None):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,logger)
        priv = read_private()

        if name is not None and serial is not None:
            raise Exception("You may not specify a cert and a serial at the same time")
        if name is None and serial is None:
            raise Exception("You must specify a cert or a serial to revoke")
        if name is not None:
            # load up the cert
            cert = X509.load_cert("%s-cert.crt"%name)
            serial = cert.get_serial_number()

        #convert serial to string
        serial = str(serial)

        # get the ca key cert and keys as strings
        with open('cacert.crt','r') as f:
            cacert = f.read()
        ca_pk = priv[0]['ca'].decode('utf-8')

        if serial not in priv[0]['revoked_keys']:
            priv[0]['revoked_keys'].append(serial)

        crl = ca_impl.gencrl(priv[0]['revoked_keys'],cacert,ca_pk)

        write_private(priv)

        # write out the CRL to the disk
        with open('cacrl.der','wb') as f:
            f.write(crl)
        convert_crl_to_pem("cacrl.der","cacrl.pem")

    finally:
        os.chdir(cwd)
    return crl

# regenerate the crl without revoking anything
def cmd_regencrl(workingdir):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,logger)
        priv = read_private()

        # get the ca key cert and keys as strings
        with open('cacert.crt','r') as f:
            cacert = f.read()
        ca_pk = str(priv[0]['ca'])

        crl = ca_impl.gencrl(priv[0]['revoked_keys'],cacert,ca_pk)

        write_private(priv)

        # write out the CRL to the disk
        with open('cacrl.der','wb') as f:
            f.write(crl)
        convert_crl_to_pem("cacrl.der","cacrl.pem")

    finally:
        os.chdir(cwd)
    return crl

def cmd_listen(workingdir,cert_path):
    #just load up the password for later
    read_private()

    serveraddr = ('', common.CRL_PORT)
    server = ThreadedCRLServer(serveraddr,CRLHandler)
    if os.path.exists('%s/cacrl.der'%workingdir):
        logger.info("Loading existing crl: %s/cacrl.der"%workingdir)
        with open('%s/cacrl.der'%workingdir,'rb') as f:
            server.setcrl(f.read())
    t = threading.Thread(target=server.serve_forever)
    logger.info("Hosting CRL on %s:%d"%(socket.getfqdn(),common.CRL_PORT))
    t.start()

    def check_expiration():
        logger.info("checking CRL for expiration every hour")
        while True:
            try:
                if os.path.exists('%s/cacrl.der'%workingdir):
                    retout = cmd_exec.run("openssl crl -inform der -in %s/cacrl.der -text -noout"%workingdir,lock=False)['retout']
                    for line in retout:
                        line = line.strip()
                        if line.startswith(b"Next Update:"):
                            expire = datetime.datetime.strptime(line[13:].decode('utf-8'),"%b %d %H:%M:%S %Y %Z")
                            # check expiration within 6 hours
                            in1hour = datetime.datetime.utcnow()+datetime.timedelta(hours=6)
                            if expire<=in1hour:
                                logger.info("Certificate to expire soon %s, re-issuing"%expire)
                                cmd_regencrl(workingdir)
                # check a little less than every hour
                time.sleep(3540)

            except KeyboardInterrupt:
                logger.info("TERM Signal received, shutting down...")
                #server.shutdown()
                break

    t2 = threading.Thread(target=check_expiration)
    t2.setDaemon(True)
    t2.start()

    def revoke_callback(revocation):
        serial = revocation.get("metadata",{}).get("cert_serial",None)
        if revocation.get('type',None) != 'revocation' or serial is None:
            logger.error("Unsupported revocation message: %s"%revocation)
            return

        logger.info("Revoking certificate: %s"%serial)
        server.setcrl(cmd_revoke(workingdir, None, serial))

    try:
        while True:
            try:
                revocation_notifier.await_notifications(revoke_callback,revocation_cert_path=cert_path)
            except Exception as e:
                logger.exception(e)
                logger.warning("No connection to revocation server, retrying in 10s...")
                time.sleep(10)
    except KeyboardInterrupt:
        logger.info("TERM Signal received, shutting down...")
        server.shutdown()
        sys.exit()

class ThreadedCRLServer(ThreadingMixIn, HTTPServer):
    published_crl = None

    def setcrl(self,crl):
        self.published_crl = crl


class CRLHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logger.info('GET invoked from ' + str(self.client_address)  + ' with uri:' + self.path)

        if self.server.published_crl is None:
            self.send_response(404)
            self.end_headers()
        else:
            # send back the CRL
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.server.published_crl)

def rmfiles(path):
    import glob
    files = glob.glob(path)
    for f in files:
        os.remove(f)

def write_private(inp):
    priv = inp[0]
    salt = inp[1]
    global global_password

    priv_encoded = yaml.dump(priv, Dumper=SafeDumper)
    key = crypto.kdf(global_password,salt)
    ciphertext = crypto.encrypt(priv_encoded,key)
    towrite = {'salt':salt,'priv':ciphertext}

    with os.fdopen(os.open('private.yml',os.O_WRONLY | os.O_CREAT,0o600), 'w') as f:
        yaml.dump(towrite,f, Dumper=SafeDumper)

def read_private():
    global global_password
    if global_password is None:
        setpassword(getpass.getpass("Please enter the password to decrypt your keystore: "))

    if os.path.exists('private.yml'):
        with open('private.yml','r') as f:
            toread = yaml.load(f, Loader=SafeLoader)
        key = crypto.kdf(global_password,toread['salt'])
        try:
            plain = crypto.decrypt(toread['priv'],key)
        except ValueError:
            raise Exception("Invalid password for keystore")

        return yaml.load(plain, Loader=SafeLoader),toread['salt']
    else:
        #file doesn't exist, just invent a salt
        return {'revoked_keys':[]},base64.b64encode(crypto.generate_random_key()).decode()

def main(argv=sys.argv):
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('-c', '--command',action='store',dest='command',required=True,help="valid commands are init,create,pkg,revoke,listen")
    parser.add_argument('-n', '--name',action='store',help='the common name of the certificate to create')
    parser.add_argument('-d','--dir',action='store',help='use a custom directory to store certificates and keys')
    parser.add_argument('-i','--insecure',action='store_true',default=False,help='create cert packages with unprotected private keys and write them to disk.  USE WITH CAUTION!')

    if common.DEVELOP_IN_ECLIPSE and len(argv)==1:
        argv=['-c','init']
        #argv=['-c','create','-n',socket.getfqdn()]
        argv=['-c','create','-n','client']
        #argv=['-c','pkg','-n','client']
        argv=['-c','revoke','-n','client']
        argv=['-c','listen','-d','ca']
    else:
        argv = argv[1:]

    # never prompt for passwords in development mode
    if common.DEVELOP_IN_ECLIPSE:
        setpassword('default')

    args = parser.parse_args(argv)

    if args.dir==None:
        if os.getuid()!=0 and common.REQUIRE_ROOT:
            logger.error("If you don't specify a working directory, this process must be run as root to access %s"%common.WORK_DIR)
            sys.exit(-1)
        workingdir = common.CA_WORK_DIR
    else:
        workingdir = args.dir

    if args.command=='init':
        cmd_init(workingdir)
    elif args.command=='create':
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_mkcert(workingdir,args.name)
    elif args.command=='pkg':
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_certpkg(workingdir,args.name,args.insecure)
    elif args.command=='revoke':
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_revoke(workingdir, args.name)
    elif args.command=='listen':
        if args.name is None:
            args.name = "%s/RevocationNotifier-cert.crt"%workingdir
            logger.warning("using default name for revocation cert %s"%args.name)
        cmd_listen(workingdir,args.name)
    else:
        logger.error("Invalid command: %s"%args.command)
        parser.print_help()
        sys.exit(-1)

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
