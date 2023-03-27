import base64
import hashlib
import json
import os
import tempfile
from typing import Optional, Union

import gpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate

from keylime import keylime_logging
from keylime.dsse import dsse
from keylime.dsse import ecdsa as dsse_ecdsa
from keylime.dsse import x509 as dsse_x509
from keylime.types import PathLike_str

logger = keylime_logging.init_logging("signing")


def verify_signature_from_file(
    key_file: Union[str, PathLike_str],
    filename: Union[str, PathLike_str],
    sig_file: Union[str, PathLike_str],
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


def verify_dsse_envelope(envelope: bytes, key: Optional[bytes] = None) -> Optional[dsse.VerifiedPayload]:
    verifiers: dsse.VerifierList

    if key:
        ec_pubkey = load_pem_public_key(key)
        assert isinstance(ec_pubkey, ec.EllipticCurvePublicKey)
        verifiers = [("user_provided_key", dsse_ecdsa.Verifier(ec_pubkey))]
    else:
        envelope_json = json.loads(envelope)

        certificates = [base64.b64decode(signer["keyid"]) for signer in envelope_json["signatures"]]
        verifiers = [
            (hashlib.sha256(cert).hexdigest(), dsse_x509.Verifier(load_pem_x509_certificate(cert)))
            for cert in certificates
        ]

    verification_result: Optional[dsse.VerifiedPayload] = None
    try:
        verification_result = dsse.Verify(envelope.decode(), verifiers)
    except ValueError as e:
        logger.warning("Unable to verify DSSE envelope: %s", e)

    return verification_result


def get_runtime_policy_keys(runtime_policy: bytes, pubkey: Optional[str] = None) -> Optional[bytes]:
    runtime_policy_json = json.loads(runtime_policy)
    if runtime_policy_json.get("payload"):
        pubkey_dir = "/var/lib/keylime/signing_keys/"
        if pubkey:
            runtime_policy_key_bytes = base64.b64decode(pubkey)
            keyid = hashlib.sha256(runtime_policy_key_bytes).hexdigest()
            pubkey_path = os.path.join(pubkey_dir, f"{keyid}.pub")
            logger.info("Writing provided DSSE public key to disk at %s", pubkey_path)
            if not os.path.exists(pubkey_dir):
                os.makedirs(pubkey_dir)
            with open(pubkey_path, "wb") as f:
                f.write(runtime_policy_key_bytes)
        else:
            runtime_policy_key_bytes = None
            for sig in runtime_policy_json["signatures"]:
                keyid = sig["keyid"]
                pubkey_path = os.path.join(pubkey_dir, f"{keyid}.pub")
                if os.path.isfile(pubkey_path):
                    logger.info("Found matching DSSE public key at %s", pubkey_path)
                    with open(pubkey_path, "rb") as f:
                        runtime_policy_key_bytes = f.read()
        return runtime_policy_key_bytes
    return None
