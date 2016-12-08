#!/usr/bin/env python

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
logger = common.init_logging('ca-util')

import sys
import os
import crypto
import base64
import argparse
import ConfigParser
import getpass
import json
import zipfile
import cStringIO
import socket

if common.CA_IMPL=='cfssl':
    import ca_impl_cfssl as ca_impl
elif common.CA_IMPL=='openssl':
    import ca_impl_openssl as ca_impl
else:
    raise Exception("Unknown CA implementation: %s"%common.CA_IMPL)
from M2Crypto import X509, EVP, BIO

config = ConfigParser.SafeConfigParser()
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
    return str(global_password)

def setpassword(pw):
    global global_password
    global_password = pw

def cmd_mkcert(workingdir,name):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,os.getuid()==0)
        priv = read_private()
        
        cacert = X509.load_cert('cacert.crt')
        ca_pk = EVP.load_key_string(str(priv[0]['ca']))
            
        cert,pk = ca_impl.mk_signed_cert(cacert,ca_pk,name,priv[0]['lastserial']+1)
        with open('%s-cert.crt'%name, 'w') as f:
            f.write(cert.as_pem())
            
        f = BIO.MemoryBuffer() 
        pk.save_key_bio(f,None)
        priv[0][name]=f.getvalue()
        f.close()
        
        #increment serial number after successful creation
        priv[0]['lastserial']+=1

        # extract the serial number
        serial = cert.get_serial_number()
        
        write_private(priv)
        
        # write out the private key with password
        with os.fdopen(os.open("%s-private.pem"%name,os.O_WRONLY | os.O_CREAT,0600), 'w') as f:
            biofile = BIO.File(f)
            pk.save_key_bio(biofile, 'aes_256_cbc', globalcb)
            biofile.close()
    
        pk.get_rsa().save_pub_key('%s-public.pem'%name)
        
        cc = X509.load_cert('%s-cert.crt'%name)
        
        if cc.verify(cacert.get_pubkey()):
            logger.info("Created certificate for name %s successfully in %s"%(name,workingdir))
        else:
            logger.errro("ERROR: Cert does not validate against CA")
    finally:
        os.chdir(cwd)
        
    return serial

def cmd_init(workingdir):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,os.getuid()==0)
        
        rmfiles("*.pem")
        rmfiles("*.crt")
        rmfiles("*.zip")
        rmfiles("private.json")
    
        cacert, ca_pk, _ = ca_impl.mk_cacert()
        
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
        
        # Sanity checks...
        cac = X509.load_cert('cacert.crt')
        if cac.verify():
            logger.info("CA certificate created successfully in %s"%workingdir)
        else:
            logger.error("ERROR: Cert does not self validate")
    finally:
        os.chdir(cwd)
        
def cmd_certpkg(workingdir,name,needfile=True):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,os.getuid()==0)
        # zip up the crt, private key, and public key
        
        with open('cacert.crt','r') as f:
            cacert = f.read()
        
        with open("%s-public.pem"%name,'rb') as f:
            pub = f.read()
            
        with open("%s-cert.crt"%name,'rb') as f:
            cert = f.read()
        
        priv = read_private()
        private = priv[0][name]
        
        with open("%s-private.pem"%name,'rb') as f:
            prot_priv = f.read()
        
        #code to create a pem formatted protected private key using the keystore password
    #     pk = EVP.load_key_string(str(priv[0][name]))
    #     f = BIO.MemoryBuffer()
    #     # globalcb will return the global password provided by the user
    #     pk.save_key_bio(f, 'aes_256_cbc', globalcb)
    #     prot_priv = f.getvalue()
    #     f.close()
        
        # no compression to avoid extraction errors in tmpfs
        sf = cStringIO.StringIO()
        with zipfile.ZipFile(sf,'w',compression=zipfile.ZIP_STORED) as f:
            f.writestr('%s-public.pem'%name,pub)
            f.writestr('%s-cert.crt'%name,cert)
            f.writestr('%s-private.pem'%name,private)
            f.writestr('cacert.crt',cacert)
        pkg = sf.getvalue()
        
        # actually output the package to disk with a protected private key
        with zipfile.ZipFile('%s-pkg.zip'%name,'w',compression=zipfile.ZIP_STORED) as f:
            f.writestr('%s-public.pem'%name,pub)
            f.writestr('%s-cert.crt'%name,cert)
            f.writestr('%s-private.pem'%name,prot_priv)
            f.writestr('cacert.crt',cacert)

        logger.info("Creating cert package for %s in %s-pkg.zip"%(name,name))
        
        return pkg
    finally:
        os.chdir(cwd)
        
def cmd_revoke(workingdir,name=None,serial=None):
    cwd = os.getcwd()
    try:
        common.ch_dir(workingdir,os.getuid()==0)
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
        ca_pk = str(priv[0]['ca'])
        
        if serial not in priv[0]['revoked_keys']:
            priv[0]['revoked_keys'].append(serial)
        
        crl = ca_impl.gencrl(priv[0]['revoked_keys'],cacert,ca_pk)
         
        write_private(priv)
        
        return crl
    finally:
        os.chdir(cwd)
    return crl

def rmfiles(path):
    import glob
    files = glob.glob(path)
    for f in files:
        os.remove(f)
        
def write_private(inp):
    priv = inp[0]
    salt = inp[1]
    global global_password
    
    priv_encoded = json.dumps(priv)
    key = crypto.kdf(global_password,salt)
    ciphertext = crypto.encrypt(priv_encoded,key)
    towrite = {'salt':salt,'priv':ciphertext}
    
    with os.fdopen(os.open('private.json',os.O_WRONLY | os.O_CREAT,0600), 'w') as f:
        json.dump(towrite,f)

def read_private():
    global global_password
    if global_password is None:
        global_password = getpass.getpass("Please enter the password to decrypt your keystore: ")

    if os.path.exists('private.json'):
        with open('private.json','r') as f:
            toread = json.load(f)
        key = crypto.kdf(global_password,toread['salt'])
        try:
            plain = crypto.decrypt(toread['priv'],key)
        except ValueError:
            raise Exception("Invalid password for keystore")
            
        return json.loads(plain),toread['salt']
    else:
        #file doesn't exist, just invent a salt
        return {'revoked_keys':[]},base64.b64encode(crypto.generate_random_key())

def main(argv=sys.argv):
    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('-c', '---command',action='store',dest='command',required=True,help="valid commands are init,create")
    parser.add_argument('-n', '--name',action='store',help='the common name of the certificate to create')
    parser.add_argument('-d','--dir',action='store',help='use a custom directory to store certificates and keys')

    if common.DEVELOP_IN_ECLIPSE and len(argv)==1:
        setpassword('test')
        argv=['-c','init']
        #argv=['-c','create','-n',socket.getfqdn()]
        argv=['-c','create','-n','crltest.llan.ll.mit.edu']
        #argv=['-c','pkg','-n','client']
        argv=['-c','revoke','-n','crltest.llan.ll.mit.edu']
    else:
        argv = argv[1:]
        
    args = parser.parse_args(argv)
    
    if args.dir==None:
        if os.getuid()!=0 and not common.DEVELOP_IN_ECLIPSE:
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
        cmd_certpkg(workingdir,args.name)
    elif args.command=='revoke':
        if args.name is None:
            logger.error("you must pass in a name for the certificate using -n (or --name)")
            parser.print_help()
            sys.exit(-1)
        cmd_revoke(workingdir, args.name)
    else:
        logger.error("Invalid command: %s"%args.command)
        parser.print_help()
        sys.exit(-1)
    
if __name__=="__main__":
    main()
