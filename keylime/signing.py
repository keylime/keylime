import tempfile
from os import PathLike
from typing import Union

import gpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from keylime import keylime_logging

logger = keylime_logging.init_logging("signing")


def verify_signature_from_file(
    key_file: Union[str, PathLike[str]],
    filename: Union[str, PathLike[str]],
    sig_file: Union[str, PathLike[str]],
    description: str,
) -> None:
    """
    Verify the file signature on disk (sig_file) using a public key on disk
    (key_file) with the file on disk (file). All inputs should be file
    paths.
    """

    with open(key_file, "rb") as fd:
        key = fd.read()
    with open(sig_file, "rb") as fd:
        sig = fd.read()
    with open(filename, "rb") as fd:
        body = fd.read()

    if verify_signature(key, sig, body):
        logger.debug("%s passed signature verification", description)
    else:
        raise Exception(
            f'{description} signature verification failed for "{filename}" against signature "{sig_file}" using key "{key_file}"'
        )


def verify_signature(key: bytes, sig: bytes, body: bytes) -> bool:
    """
    Verify the file signature (sig) using a public key (key)
    with the file (file).
    """

    # Inspect the public key to determine what kind of key it is.
    key_header = key.decode("utf-8").split("\n")[0].strip()

    verified = False

    try:
        # PGP
        if key_header == "-----BEGIN PGP PUBLIC KEY BLOCK-----":
            verified = False
            with tempfile.TemporaryDirectory() as gpg_homedir:
                ctx = gpg.Context(home_dir=gpg_homedir)
                try:
                    logger.debug("Importing GPG key")
                    assert callable(ctx.key_import)
                    result = ctx.key_import(key)
                except Exception as e:
                    raise Exception("Unable to import GPG key") from e

                if hasattr(result, "considered"):
                    _, result = ctx.verify(body, sig)
                    verified = result.signatures[0].status == 0

        # OpenSSL
        elif key_header == "-----BEGIN PUBLIC KEY-----":
            logger.debug("Importing ECDSA key")
            pubkey = load_pem_public_key(key)

            if isinstance(pubkey, ec.EllipticCurvePublicKey):
                logger.debug("EC public key successfully imported, verifying signature...")
                try:
                    pubkey.verify(sig, body, ec.ECDSA(hashes.SHA256()))
                    verified = True
                except InvalidSignature:
                    verified = False
            else:
                raise Exception(f"Unsupported public key algorithm: {type(pubkey)}")
        else:
            raise Exception("Unrecognized key type!")

    except Exception as e:
        logger.warning("Unable to verify signature: %s", e)
        verified = False

    return verified
