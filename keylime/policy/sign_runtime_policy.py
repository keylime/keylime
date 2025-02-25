"""Module to assist with signing Keylime runtime policies using DSSE."""

import argparse
import json
from json.decoder import JSONDecodeError
from typing import TYPE_CHECKING, Any, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from keylime.dsse import dsse, ecdsa, x509
from keylime.ima import ima
from keylime.policy.logger import Logger

if TYPE_CHECKING:
    # FIXME: how to make mypy and pylint happy here?
    _SubparserType = argparse._SubParsersAction[argparse.ArgumentParser]  # pylint: disable=protected-access
else:
    _SubparserType = Any


logger = Logger().logger()

KEYLIME_PAYLOAD_TYPE = "application/vnd.keylime+json"
KEYLIME_DEFAULT_EC_KEY_FILE = "keylime-ecdsa-key.pem"

VALID_BACKENDS = ["ecdsa", "x509"]


def get_arg_parser(create_parser: _SubparserType, parent_parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Perform the setup of the command-line arguments for this module."""
    sign_p = create_parser.add_parser("runtime", help="sign runtime policies", parents=[parent_parser])

    sign_p.add_argument(
        "-o",
        "--output",
        dest="output_file",
        required=False,
        help="The output file path for the DSSE-signed policy",
        default="/dev/stdout",
    )
    sign_p.add_argument(
        "-r",
        "--runtime-policy",
        dest="policy",
        required=True,
        help="The location of the runtime policy file",
        default="",
    )
    sign_p.add_argument(
        "-k",
        "--keyfile",
        dest="keyfile",
        required=False,
        help="The EC private key to sign the policy with",
        default="",
    )
    sign_p.add_argument(
        "-p",
        "--keypath",
        dest="keypath",
        required=False,
        help="The filename to write the created private key, if one is not provided via the --keyfile argument",
        default="",
    )
    sign_p.add_argument(
        "-b",
        "--backend",
        dest="backend",
        required=False,
        help="DSSE backend to use; either ecdsa or x509",
        choices=VALID_BACKENDS,
        type=str.lower,
        default="ecdsa",
    )
    sign_p.add_argument(
        "-c",
        "--cert-outfile",
        dest="cert_outfile",
        required=False,
        help="The output file path for the x509 certificate, if using x509 DSSE backend",
        default="",
    )

    sign_p.set_defaults(func=sign_runtime_policy)

    return sign_p


def _get_signer(
    backend: str,
    in_ec_keyfile_path: Optional[str] = None,
    out_keyfile_path: Optional[str] = None,
    out_certfile: Optional[str] = None,
) -> Optional[dsse.Signer]:
    if backend not in VALID_BACKENDS:
        logger.debug("Invalid backend '%s'; the valid alternatives are: %s", backend, VALID_BACKENDS)
        return None

    if in_ec_keyfile_path and out_keyfile_path:
        logger.debug("Both the EC private key and the output key path cannot be specified at once")
        return None

    if not out_keyfile_path:
        out_keyfile_path = KEYLIME_DEFAULT_EC_KEY_FILE

    ec_privkey: Optional[ec.EllipticCurvePrivateKey] = None
    if in_ec_keyfile_path:
        try:
            with open(in_ec_keyfile_path, "rb") as pem_in:
                pemlines = pem_in.read()
        except FileNotFoundError:
            logger.error("The specified key '%s' does not exist", in_ec_keyfile_path)
            return None
        privkey = load_pem_private_key(pemlines, None, default_backend())

        if not isinstance(privkey, ec.EllipticCurvePrivateKey):
            logger.error("Only elliptic curve keys are supported")
            return None
        ec_privkey = privkey

    signer: Optional[dsse.Signer] = None

    if backend == "ecdsa":
        if ec_privkey:
            signer = ecdsa.Signer(ec_privkey)
        else:
            signer = ecdsa.Signer.create(out_keyfile_path)
    elif backend == "x509":
        if out_certfile is None or out_certfile == "":
            logger.error("x509 backend and no cerficate output file specified")
            return None

        if ec_privkey:
            signer = x509.Signer(ec_privkey, certificate_path=out_certfile)
        else:
            signer = x509.Signer.create(out_keyfile_path, certificate_path=out_certfile)

    return signer


def _sign_policy(signer: dsse.Signer, policy_fpath: str) -> Optional[str]:
    try:
        # Let us validate the policy first.
        with open(policy_fpath, "rb") as f:
            policy = json.load(f)
        ima.validate_runtime_policy(policy)

        # Now we can sign it.
        unsigned_policy = json.dumps(policy)
        signed_policy = dsse.Sign(
            payloadType=KEYLIME_PAYLOAD_TYPE, payload=unsigned_policy.encode("UTF-8"), signer=signer
        )
    except FileNotFoundError:
        logger.error("The runtime policy file specified (%s) does not seem to exist", policy_fpath)
        return None
    except (ima.ImaValidationError, JSONDecodeError):
        logger.error(
            "Unable to validate the runtime policy '%s'; please make sure to provide a valid runtime policy",
            policy_fpath,
        )
        return None
    except Exception as exc:
        logger.error("Error while attempting to sign the runtime policy '%s': %s", policy_fpath, exc)
        return None

    return signed_policy


def sign_runtime_policy(args: argparse.Namespace) -> Optional[str]:
    """Sign a runtime policy."""
    if args.keyfile and args.keypath:
        logger.error("Only one of keyfile or keypath must be specified at once")
        return None

    signer = _get_signer(
        backend=args.backend,
        in_ec_keyfile_path=args.keyfile,
        out_keyfile_path=args.keypath,
        out_certfile=args.cert_outfile,
    )

    if not signer:
        logger.error("Unable to obtain a valid signer from the input data")
        return None

    signed_policy = _sign_policy(signer, args.policy)
    if signed_policy is None:
        logger.debug("_sign_policy() failed; policy: %s", args.policy)
        return None

    try:
        with open(args.output_file, "wb") as f:
            f.write(signed_policy.encode("UTF-8"))
    except Exception as exc:
        logger.error("Unable to write signed policy to destination file '%s': %s", args.output_file, exc)
        return None

    return signed_policy
