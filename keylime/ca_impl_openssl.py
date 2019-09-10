'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2016 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''

import configparser
import time

from M2Crypto import X509, EVP, RSA, ASN1
from keylime import common
from keylime import keylime_logging

config = configparser.ConfigParser()
config.read(common.CONFIG_FILE)

def mk_cert_valid(cert, days=365):
    """
    Make a cert valid from now and til 'days' from now.
    Args:
       cert -- cert to make valid
       days -- number of days cert is valid for from now.
    """
    t = int(time.time())
    now = ASN1.ASN1_UTCTIME()
    now.set_time(t)
    expire = ASN1.ASN1_UTCTIME()
    expire.set_time(t + days * 24 * 60 * 60)
    cert.set_not_before(now)
    cert.set_not_after(expire)


def mk_request(bits, cn):
    """
    Create a X509 request with the given number of bits in they key.
    Args:
      bits -- number of RSA key bits
      cn -- common name in the request
    Returns a X509 request and the private key (EVP)
    """
    pk = EVP.PKey()
    x = X509.Request()
    rsa = RSA.gen_key(bits, 65537, lambda: None)
    pk.assign_rsa(rsa)
    x.set_pubkey(pk)
    name = x.get_subject()
    name.C = config.get('ca','cert_country')
    name.CN = cn
    name.ST = config.get('ca','cert_state')
    name.L = config.get('ca','cert_locality')
    name.O = config.get('ca','cert_organization')
    name.OU = config.get('ca','cert_org_unit')
    x.sign(pk,'sha256')
    return x, pk


def mk_cacert(name=None):
    """
    Make a CA certificate.
    Returns the certificate, private key and public key.
    """
    req, pk = mk_request(config.getint('ca','cert_bits'),config.get('ca','cert_ca_name'))
    pkey = req.get_pubkey()
    cert = X509.X509()
    cert.set_serial_number(1)
    cert.set_version(2)
    mk_cert_valid(cert,config.getint('ca','cert_ca_lifetime'))

    if name==None:
        name = config.get('ca','cert_ca_name')

    issuer = X509.X509_Name()
    issuer.C = config.get('ca','cert_country')
    issuer.CN = name
    issuer.ST = config.get('ca','cert_state')
    issuer.L = config.get('ca','cert_locality')
    issuer.O = config.get('ca','cert_organization')
    issuer.OU = config.get('ca','cert_org_unit')
    cert.set_issuer(issuer)
    cert.set_subject(cert.get_issuer())
    cert.set_pubkey(pkey)
    cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
    cert.add_ext(X509.new_extension('subjectKeyIdentifier', str(cert.get_fingerprint())))
    cert.add_ext(X509.new_extension('crlDistributionPoints','URI:http://localhost/crl.pem'))
    cert.add_ext(X509.new_extension('keyUsage', 'keyCertSign, cRLSign'))
    cert.sign(pk, 'sha256')
    return cert, pk, pkey

def mk_signed_cert(cacert,ca_pk,name,serialnum):
    """
    Create a CA cert + server cert + server private key.
    """
    # unused, left for history.
    cert_req, pk = mk_request(config.getint('ca','cert_bits'), cn=name)

    cert = X509.X509()
    cert.set_serial_number(serialnum)
    cert.set_version(2)
    mk_cert_valid(cert)
    cert.add_ext(X509.new_extension('nsComment', 'SSL sever'))
    cert.add_ext(X509.new_extension('subjectAltName','DNS:%s'%name))
    cert.add_ext(X509.new_extension('crlDistributionPoints','URI:http://localhost/crl.pem'))

    cert.set_subject(cert_req.get_subject())
    cert.set_pubkey(cert_req.get_pubkey())
    cert.set_issuer(cacert.get_issuer())
    cert.sign(ca_pk, 'sha256')
    return cert, pk

def gencrl(_,a,b):
    logger = keylime_logging.init_logging('ca_impl_openssl')
    logger.warning("CRL creation with openssl is not supported")
    return ""
