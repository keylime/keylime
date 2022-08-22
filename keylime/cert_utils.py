from cryptography.hazmat.primitives.serialization import load_der_public_key
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459


# Issue #944 -- python-cryptography won't parse malformed certs,
# such as some Nuvoton ones we have encountered in the field.
# Unfortunately, we still have to deal with such certs anyway.
# Let's read the EK cert with pyasn1 instead of python-cryptography.
def read_x509_der_cert_pubkey(der_cert_data):
    """Returns the public key of a DER-encoded X.509 certificate"""
    der509 = decoder.decode(der_cert_data, asn1Spec=rfc2459.Certificate())[0]
    return load_der_public_key(encoder.encode(der509["tbsCertificate"]["subjectPublicKeyInfo"]))
