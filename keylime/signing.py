'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import tempfile
import gnupg

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from keylime import keylime_logging

logger = keylime_logging.init_logging('signing')

def verify_signature_from_file(key_file, filename, sig_file, file_description):
    """
       Verify the file signature on disk (sig_file) using a public key on disk
       (key_file) with the file on disk (file). All inputs should be file
       paths.
    """

    with open(key_file, 'rb') as key_f:
        key = key_f.read()
    with open(sig_file, 'rb') as sig_f:
        sig = sig_f.read()
    with open(filename, 'rb') as file_f:
        file = file_f.read()

    if verify_signature(key, sig, file):
        logger.debug("%s passed signature verification", file_description.capitalize())
    else:
        raise Exception(f"{file_description.capitalize()} signature verification failed comparing {file_description} ({filename}) against sig_file ({sig_file})")


def verify_signature(key, sig, file):
    """
       Verify the file signature (sig) using a public key (key)
       with the file (file).
    """

    # Inspect the public key to determine what kind of key it is.
    key_header = key.decode('utf-8').split('\n')[0].strip()

    # PGP
    if key_header == "-----BEGIN PGP PUBLIC KEY BLOCK-----":
        gpg = gnupg.GPG()
        logger.debug("Importing GPG key")
        gpg_imported = gpg.import_keys(key.decode("utf-8"))
        if gpg_imported.count == 1: # pylint: disable=E1101
            logger.debug("GPG key successfully imported")
        else:
            raise Exception("Unable to import GPG key")

        # The Python PGP library won't let you read a signature from memory, hence this hack.
        with tempfile.NamedTemporaryFile() as temp_sig:
            temp_sig.write(sig)
            temp_sig.flush()
            verified = gpg.verify_data(temp_sig.name, file)

    # OpenSSL
    elif key_header == "-----BEGIN PUBLIC KEY-----":
        logger.debug("Importing ECDSA key")
        pubkey = load_pem_public_key(key)

        if isinstance(pubkey, ec.EllipticCurvePublicKey):
            logger.debug("EC public key successfully imported, verifying signature...")
            try:
                pubkey.verify(sig, file, ec.ECDSA(hashes.SHA256()))
                verified = True
            except InvalidSignature:
                verified = False
        else:
            raise Exception(f"Unsupported public key algorithm: {type(pubkey)}")
    else:
        raise Exception("Unrecognized key type!")

    return verified
