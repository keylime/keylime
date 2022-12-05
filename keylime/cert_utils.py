import io
import os.path
import subprocess
import sys
from typing import Dict, Optional

from cryptography import exceptions as crypto_exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import pem, rfc2459

from keylime import keylime_logging, tpm_ek_ca

# Issue #944 -- python-cryptography won't parse malformed certs,
# such as some Nuvoton ones we have encountered in the field.
# Unfortunately, we still have to deal with such certs anyway.

# Here we provide some helpers that use pyasn1 to parse the certificates
# when parsing them with python-cryptography fails, and in this case, we
# try to read the parsed certificate again into python-cryptograhy.

logger = keylime_logging.init_logging("cert_utils")


def x509_der_cert(der_cert_data: bytes) -> Certificate:
    """Load an x509 certificate provided in DER format
    :param der_cert_data: the DER bytes of the certificate
    :type der_cert_data: bytes
    :returns: cryptography.x509.Certificate
    """
    try:
        return x509.load_der_x509_certificate(data=der_cert_data, backend=default_backend())
    except Exception as e:
        logger.warning("Failed to parse DER data with python-cryptography: %s", e)
        pyasn1_cert = decoder.decode(der_cert_data, asn1Spec=rfc2459.Certificate())[0]
        return x509.load_der_x509_certificate(data=encoder.encode(pyasn1_cert), backend=default_backend())


def x509_pem_cert(pem_cert_data: str) -> Certificate:
    """Load an x509 certificate provided in PEM format
    :param pem_cert_data: the base-64 encoded PEM certificate
    :type pem_cert_data: str
    :returns: cryptography.x509.Certificate
    """
    try:
        return x509.load_pem_x509_certificate(data=pem_cert_data.encode("utf-8"), backend=default_backend())
    except Exception as e:
        logger.warning("Failed to parse PEM data with python-cryptography: %s", e)
        # Let's read the DER bytes from the base-64 PEM.
        der_data = pem.readPemFromFile(io.StringIO(pem_cert_data))
        # Now we can load it as we do in x509_der_cert().
        pyasn1_cert = decoder.decode(der_data, asn1Spec=rfc2459.Certificate())[0]
        return x509.load_der_x509_certificate(data=encoder.encode(pyasn1_cert), backend=default_backend())


def verify_ek(ekcert: bytes, tpm_cert_store: str) -> bool:
    """Verify that the provided EK certificate is signed by a trusted root
    :param ekcert: The Endorsement Key certificate in DER format
    :param tpm_cert_store: The path for the TPM certificate store
    :returns: True if the certificate can be verified, False otherwise
    """
    try:
        trusted_certs = tpm_ek_ca.cert_loader(tpm_cert_store)
    except Exception as e:
        logger.warning("Error loading trusted certificates from the TPM cert store: %s", e)
        return False

    try:
        ek509 = x509_der_cert(ekcert)
        for cert_file, pem_cert in trusted_certs.items():
            signcert = x509_pem_cert(pem_cert)
            if ek509.issuer != signcert.subject:
                continue

            signcert_pubkey = signcert.public_key()
            try:
                if isinstance(signcert_pubkey, RSAPublicKey):
                    assert ek509.signature_hash_algorithm is not None
                    signcert_pubkey.verify(
                        ek509.signature,
                        ek509.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        ek509.signature_hash_algorithm,
                    )
                elif isinstance(signcert_pubkey, EllipticCurvePublicKey):
                    assert ek509.signature_hash_algorithm is not None
                    signcert_pubkey.verify(
                        ek509.signature,
                        ek509.tbs_certificate_bytes,
                        ec.ECDSA(ek509.signature_hash_algorithm),
                    )
                else:
                    logger.warning("Unsupported public key type: %s", type(signcert_pubkey))
                    continue
            except crypto_exceptions.InvalidSignature:
                continue

            logger.debug("EK cert matched cert: %s", cert_file)
            return True
    except Exception as e:
        # Log the exception so we don't lose the raw message
        logger.exception(e)
        raise Exception("Error processing ek/ekcert. Does this TPM have a valid EK?").with_traceback(sys.exc_info()[2])

    logger.error("No Root CA matched EK Certificate")
    return False


def verify_ek_script(script: Optional[str], env: Optional[Dict[str, str]], cwd: Optional[str]) -> bool:
    if script is None:
        logger.warning("External check script (%s) not specified", script)
        return False

    script_path = os.path.abspath(script)
    if not os.path.isfile(script_path):
        if cwd is None or not os.path.isfile(os.path.abspath(os.path.join(cwd, script))):
            logger.warning("External check script (%s) not found; please make sure its path is correct", script)
            return False
        script_path = os.path.abspath(os.path.join(cwd, script))

    try:
        proc = subprocess.run(
            [script_path],
            env=env,
            shell=False,
            cwd=cwd,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            errmsg = ""
            if proc.stdout is not None:
                errmsg = proc.stdout.decode("utf-8")
            logger.error("External check script failed to validate EK: %s", errmsg)
            return False
        logger.debug("External check script successfully to validated EK")
        if proc.stdout is not None:
            logger.info("ek_check output: %s", proc.stdout.decode("utf-8"))
    except subprocess.CalledProcessError as e:
        logger.error("Error while trying to run external check script to validate EK: %s", e)
        return False
    return True
