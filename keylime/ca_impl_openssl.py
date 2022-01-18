'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from keylime import config
from keylime import keylime_logging


def mk_cert_valid(cert_req, days=365):
    """
    Make a cert valid from now and til 'days' from now.
    Args:
       cert_req -- cryptography.x509.base.CertificateBuilder
       days -- number of days cert is valid for from now.
    Returns: updated cryptography.x509.base.CertificateBuilder
    """

    one_day = datetime.timedelta(1, 0, 0)
    today = datetime.datetime.now(datetime.timezone.utc)
    cert_req = cert_req.not_valid_before(today)
    cert_req = cert_req.not_valid_after(today + (one_day * days))
    return cert_req


def mk_name(common_name):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, config.get("ca", "cert_country")),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, config.get("ca", "cert_state")
            ),
            x509.NameAttribute(
                NameOID.LOCALITY_NAME, config.get("ca", "cert_locality")
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, config.get("ca", "cert_organization")
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, config.get("ca", "cert_org_unit")
            ),
        ]
    )


def mk_request(bits, common_name):
    """
    Create a X509 request with the given number of bits in they key.
    Args:
      bits -- number of RSA key bits
      common_name -- common name in the request
    Returns a X509 request and the private key
    """

    privkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend(),
    )

    cert_req = x509.CertificateBuilder()

    subject = mk_name(common_name)
    cert_req = cert_req.subject_name(subject)
    return cert_req, privkey


def mk_cacert(name=None):
    """
    Make a CA certificate.
    Returns the certificate, private key and public key.
    """

    if name is None:
        name = config.get("ca", "cert_ca_name")
    cert_req, privkey = mk_request(config.getint("ca", "cert_bits"), name)

    pubkey = privkey.public_key()
    cert_req = cert_req.public_key(pubkey)

    cert_req = cert_req.serial_number(1)
    cert_req = mk_cert_valid(cert_req, config.getint("ca", "cert_ca_lifetime"))
    cert_req = cert_req.issuer_name(mk_name(name))

    # Extensions.
    extensions = [
        # Basic Constraints.
        x509.BasicConstraints(ca=True, path_length=None),
        # Subject Key Identifier.
        x509.SubjectKeyIdentifier.from_public_key(pubkey),
        # CRL Distribution Points.
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier("http://localhost/crl.pem"),
                    ],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]
        ),
        # Key Usage.
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
    ]

    for ext in extensions:
        cert_req = cert_req.add_extension(ext, critical=False)

    cert = cert_req.sign(
        private_key=privkey,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    return cert, privkey, pubkey


def mk_signed_cert(cacert, ca_privkey, name, serialnum):
    """
    Create a CA cert + server cert + server private key.
    """

    cert_req, privkey = mk_request(config.getint("ca", "cert_bits"), common_name=name)
    pubkey = privkey.public_key()
    cert_req = cert_req.public_key(pubkey)

    cert_req = cert_req.serial_number(serialnum)
    cert_req = mk_cert_valid(cert_req)
    cert_req = cert_req.issuer_name(cacert.issuer)

    # Extensions.
    extensions = [
        # OID 2.16.840.1.113730.1.13 is Netscape Comment.
        # http://oid-info.com/get/2.16.840.1.113730.1.13
        x509.UnrecognizedExtension(
            oid=x509.ObjectIdentifier("2.16.840.1.113730.1.13"),
            value=b"SSL Server",
        ),
        # Subject Alternative Name.
        x509.SubjectAlternativeName([x509.DNSName(name)]),
        # CRL Distribution Points.
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier("http://localhost/crl.pem"),
                    ],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                ),
            ]
        ),
    ]

    for ext in extensions:
        cert_req = cert_req.add_extension(ext, critical=False)

    cert = cert_req.sign(
        private_key=ca_privkey,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )
    return cert, privkey


def gencrl(_, a, b):
    del a, b
    logger = keylime_logging.init_logging('ca_impl_openssl')
    logger.warning("CRL creation with openssl is not supported")
    return b""
