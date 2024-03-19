import argparse
import sys
from typing import NoReturn, Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from keylime.dsse import dsse, ecdsa, x509

# pylint: disable=pointless-string-statement
"""
This script signs Keylime runtime policies using DSSE.

Example usage:

To generate an ECDSA key and sign a runtime policy:

```
python sign_runtime_policy.py -r <runtime policy path> -o keylime-policy-signed.json
```

To sign a runtime policy with an inline x509 certificate using a user-provided key:

```
python sign_runtime_policy.py -r <runtime policy path> -k private.pem -b x509 -o keylime-policy-signed.json
```

To view help and see all available options:

```
python sign_runtime_policy.py -h
```
"""


def main() -> None:
    parser = ConversionParser()
    parser.add_argument("-r", "--runtime_policy", help="Runtime policy file location", action="store")
    parser.add_argument("-k", "--keyfile", help="Private key to sign policy with", action="store")
    parser.add_argument(
        "-p",
        "--keypath",
        help="Filename to write created private key if -k is not specified",
        action="store",
    )
    parser.add_argument(
        "-b", "--backend", help="DSSE backend to use; either ecdsa or x509", action="store", default="ecdsa"
    )
    parser.add_argument("-o", "--output_file", help="Output file path for DSSE-signed policy", action="store")
    parser.add_argument(
        "-c",
        "--certificate_output_file",
        help="Output file path for x509 certificate, if using x509 DSSE backend",
        action="store",
        default="certificate.crt",
    )

    # print help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()
    if not args.runtime_policy:
        print("Runtime policy is required!")
        sys.exit(1)
    elif args.backend not in ["ecdsa", "x509"]:
        print("Unsupported DSSE backend!")
        sys.exit(1)
    elif args.keyfile and args.keypath:
        print("Only one of -k and -p may be specified at once!")
        sys.exit(1)
    elif not args.output_file:
        print("An output file path (-o, --output_file) is required to write new policy!")
        sys.exit(1)

    if not args.keypath:
        args.keypath = "keylime-ecdsa-key"

    private_key: Optional[ec.EllipticCurvePrivateKey] = None
    if args.keyfile:
        with open(args.keyfile, "rb") as pem_in:
            pemlines = pem_in.read()
        privkey = load_pem_private_key(pemlines, None, default_backend())
        if not isinstance(privkey, ec.EllipticCurvePrivateKey):
            print("Only elliptic curve keys are supported!")
            sys.exit(1)
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
        # This shouldn't happen
        print("No valid signer found!")
        sys.exit(1)

    payload_type = "application/vnd.keylime+json"

    with open(args.runtime_policy, "rb") as f:
        unsigned_policy = f.read()

    signed_policy = dsse.Sign(payloadType=payload_type, payload=unsigned_policy, signer=signer)

    with open(args.output_file, "wb") as f:
        f.write(signed_policy.encode())


class ConversionParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        sys.stderr.write(f"error: {message}\n")
        self.print_help(sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
