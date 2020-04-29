import subprocess
import sys
import os
import shutil
import time
import shlex
import configparser

from keylime import common
from keylime import  keylime_logging
from keylime import secure_mount
from keylime import ca_util

from M2Crypto import X509, EVP, BIO

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

logger = keylime_logging.init_logging('start_cfssl')

config = configparser.ConfigParser()
config.read(common.CONFIG_FILE)

tlsdir = common.CA_WORK_DIR

def main():
    if shutil.which("cfssl") is None:
        logger.error("cfssl binary not found in the path.  Please install cfssl or change the setting \"ca_implementation\" in keylime.conf")
        print("cfssl binary not found in the path.  Please install cfssl or change the setting \"ca_implementation\" in keylime.conf")
        sys.exit(1)

    # check CRL distribution point
    disturl = config.get('ca','cert_crl_dist')
    if disturl == 'default':
        disturl = "http://%s:%s/crl.der"%(socket.getfqdn(),common.CRL_PORT)

    csr = {"CN": config.get('ca','cert_ca_name'),
           "key": {
               "algo": "rsa",
               "size": config.getint('ca','cert_bits')
               },
           "names": [
               {
                   "C": config.get('ca','cert_country'),
                   "L": config.get('ca','cert_locality'),
                   "O": config.get('ca','cert_organization'),
                   "OU": config.get('ca','cert_org_unit'),
                   "ST": config.get('ca','cert_state')
                   }
                     ]
           }

    cfsslconfig  = {
        "signing": {
            "default": {
                "usages": ["client auth","server auth","key agreement","key encipherment","signing","digital signature","data encipherment"],
                "expiry": "8760h",
                "crl_url": disturl,
            }
        }
    }
    secdir = secure_mount.mount()
    env = os.environ.copy()
    env['PATH']=env['PATH']+":/usr/local/bin"

    ca_pk = None

    if not os.path.exists(tlsdir) or not os.path.exists("%s/cacert.crt"%tlsdir):
        with open('%s/ca_csr.json'%secdir, 'w') as f:
            json.dump(csr, f)

        mkcacmd = shlex.split("cfssl gencert -initca %s/ca_csr.json"%(secdir))
        try:
            output = subprocess.check_output(mkcacmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newline=True)
            pk_str = output['result']['private_key']
            ca_pk = EVP.load_key_string(body['result']['private_key'].encode('utf-8'))
            cacert = X509.load_cert_string(body['result']['certificate'].encode('utf-8'))
            pkey = cert.get_pubkey()
            f = BIO.MemoryBuffer()
            ca_pk.save_key_bio(f,None)
            priv[0]['ca']=f.getvalue()
            f.close()

            # store the last serial number created.
            # the CA is always serial # 1
            priv[0]['lastserial'] = 1

            ca.util.write_private(priv)
        except Exception as e:
            print(e)
    else:
        workingdir = tlsdir
        common.ch_dir(workingdir,logger)
        priv = ca_util.read_private()

        # get the ca key cert and keys as strings
        with open('cacert.crt','r') as f:
            cacert = f.read()
        ca_pk = str(priv[0]['ca'])

    # need to temporarily write out the private key with no password
    # to tmpfs
    ca_pk.save_key('%s/ca-key.pem'%secdir, None)
    with open('%s/cfsslconfig.yml'%secdir,'w') as f:
        json.dump(cfsslconfig, f)

    cmdline = "-config=%s/cfsslconfig.yml"%secdir

    priv_key = os.path.abspath("%s/ca-key.pem"%secdir)
    cmdline += " -ca-key %s -ca cacert.crt"%(priv_key)

    cmd = "cfssl serve -loglevel=1 %s "%cmdline[1:]
    cmd = shlex.split(cmd)

    cfsslproc = subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True)

    if cfsslproc.returncode is not None:
        raise Exception("Unable to launch %: failed with code "%(cmd,cfsslproc.returncode))

    logger.debug("Waiting for cfssl to start...")
    while True:
        line = cfsslproc.stdout.readline()
        if(line != ""):
            print(line.rstrip())

        if "Now listening on" in line:
            time.sleep(0.2)# give cfssl a little more time to get started
            logger.debug("cfssl started successfully")
            print("cfssl started successfully")
            break

        if "bind: address already in use" in line:
            logger.debug("cfssl could not start. bind already in use")
            print("cfssl could not start. bind already in use")
            break

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print(e)
