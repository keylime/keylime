"""Module to assist with signing Keylime runtime policies using DSSE."""

import argparse
import logging
from typing import TYPE_CHECKING, Any, Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from keylime.dsse import dsse, ecdsa, x509

if TYPE_CHECKING:
    # FIXME: how to make mypy and pylint happy here?
    _SubparserType = argparse._SubParsersAction[argparse.ArgumentParser]  # pylint: disable=protected-access
else:
    _SubparserType = Any

logger = logging.getLogger("policy.sign_runtime_policy")

KEYLIME_PAYLOAD_TYPE = "application/vnd.keylime+json"
KEYLIME_DEFAULT_EC_KEY_FILE = "keylime-ecdsa-key.pem"


def get_arg_parser(create_parser: _SubparserType, parent_parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Perform the setup of the command-line arguments for this module."""
    sign_p = create_parser.add_parser("runtime", help="create runtime policies", parents=[parent_parser])

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
        dest="sign_policy",
        required=True,
        help="The location of the runtime policy file",
        default="",
    )
    sign_p.add_argument(
        "-k",
        "--keyfile",
        dest="keyfile",
        required=False,
        help="The private key to sign the policy with",
        default="",
    )
    sign_p.add_argument(
        "-p",
        "--keypath",
        dest="keypath",
        required=False,
        help="The filename to write the created private key, " "if one is not provided via the --keyfile argument",
        default="",
    )
    sign_p.add_argument(
        "-b",
        "--backend",
        dest="backend",
        required=False,
        help="DSSE backend to use; either ecdsa or x509",
        choices=["ecdsa", "x509"],
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

    sign_p.set_defaults(func=sign_sign_policy)

    return sign_p


def sign_sign_policy(args: argparse.Namespace) -> Optional[str]:
    """Sign a runtime policy."""
    if args.keyfile and args.keypath:
        logger.error("Only one of keyfile or keypath must be specified at once")
        return None

    if not args.keypath:
        args.keypath = KEYLIME_DEFAULT_EC_KEY_FILE

    private_key: Optional[ec.EllipticCurvePrivateKey] = None
    if args.keyfile:
        with open(args.keyfile, "rb") as pem_in:
            pemlines = pem_in.read()
        privkey = load_pem_private_key(pemlines, None, default_backend())
        if not isinstance(privkey, ec.EllipticCurvePrivateKey):
            logger.error("Only elliptic curve keys are supported")
            return None
        private_key = privkey

    signer: Union[dsse.Signer, None] = None
    if args.backend == "ecdsa":
        if private_key:
            signer = ecdsa.Signer(private_key)
        else:
            signer = ecdsa.Signer.create(args.keypath)
    elif args.backend == "x509":
        if private_key:
            signer = x509.Signer(private_key, certificate_path=args.certificate_output_file)
        else:
            signer = x509.Signer.create(args.keypath, certificate_path=args.certificate_output_file)

    if not signer:
        # This shouldn't happen.
        logger.error("No valid signer found")
        return None

    with open(args.sign_policy, "rb") as f:
        unsigned_policy = f.read()

    signed_policy = dsse.Sign(payloadType=KEYLIME_PAYLOAD_TYPE, payload=unsigned_policy, signer=signer)

    with open(args.output_file, "wb") as f:
        f.write(signed_policy.encode())

    return signed_policy
