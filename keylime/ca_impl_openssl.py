'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import time

from M2Crypto import X509, EVP, RSA, ASN1

from keylime import config
from keylime import keylime_logging


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
    name.C = config.get('ca', 'cert_country')
    name.CN = cn
    name.ST = config.get('ca', 'cert_state')
    name.L = config.get('ca', 'cert_locality')
    name.O = config.get('ca', 'cert_organization')
    name.OU = config.get('ca', 'cert_org_unit')
    x.sign(pk, 'sha256')
    return x, pk


def mk_cacert(name=None):
    """
    Make a CA certificate.
    Returns the certificate, private key and public key.
    """
    req, pk = mk_request(config.getint('ca', 'cert_bits'),
                         config.get('ca', 'cert_ca_name'))
    pkey = req.get_pubkey()
    cert = X509.X509()
    cert.set_serial_number(1)
    cert.set_version(2)
    mk_cert_valid(cert, config.getint('ca', 'cert_ca_lifetime'))

    if name is None:
        name = config.get('ca', 'cert_ca_name')

    issuer = X509.X509_Name()
    issuer.C = config.get('ca', 'cert_country')
    issuer.CN = name
    issuer.ST = config.get('ca', 'cert_state')
    issuer.L = config.get('ca', 'cert_locality')
    issuer.O = config.get('ca', 'cert_organization')
    issuer.OU = config.get('ca', 'cert_org_unit')
    cert.set_issuer(issuer)
    cert.set_subject(cert.get_issuer())
    cert.set_pubkey(pkey)
    cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
    cert.add_ext(X509.new_extension(
        'subjectKeyIdentifier', str(cert.get_fingerprint())))
    cert.add_ext(X509.new_extension(
        'crlDistributionPoints', 'URI:http://localhost/crl.pem'))
    cert.add_ext(X509.new_extension('keyUsage', 'keyCertSign, cRLSign'))
    cert.sign(pk, 'sha256')
    return cert, pk, pkey


def mk_signed_cert(cacert, ca_pk, name, serialnum):
    """
    Create a CA cert + server cert + server private key.
    """
    # unused, left for history.
    cert_req, pk = mk_request(config.getint('ca', 'cert_bits'), cn=name)

    cert = X509.X509()
    cert.set_serial_number(serialnum)
    cert.set_version(2)
    mk_cert_valid(cert)
    cert.add_ext(X509.new_extension('nsComment', 'SSL sever'))
    cert.add_ext(X509.new_extension('subjectAltName', 'DNS:%s' % name))
    cert.add_ext(X509.new_extension(
        'crlDistributionPoints', 'URI:http://localhost/crl.pem'))

    cert.set_subject(cert_req.get_subject())
    cert.set_pubkey(cert_req.get_pubkey())
    cert.set_issuer(cacert.get_issuer())
    cert.sign(ca_pk, 'sha256')
    return cert, pk


def gencrl(_, a, b):
    del a, b
    logger = keylime_logging.init_logging('ca_impl_openssl')
    logger.warning("CRL creation with openssl is not supported")
    return ""
