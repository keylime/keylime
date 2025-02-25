"""
SPDX-License-Identifier: Apache-2.0
Copyright 2024 Red Hat, Inc.
"""

import argparse
import os
import tempfile
import unittest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from keylime.cert_utils import is_x509_cert
from keylime.policy import sign_runtime_policy
from keylime.policy.logger import Logger
from keylime.signing import verify_dsse_envelope

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "sign-runtime-policy"))
EC_PRIVKEY = os.path.join(DATA_DIR, "ec-p521-private.pem")
EC_PUBKEY = os.path.join(DATA_DIR, "ec-p521-public.pem")
RSA_PRIVKEY = os.path.join(DATA_DIR, "rsa-4096-private.pem")

POLICY = os.path.join(DATA_DIR, "runtime-policy.json")
POLICY_EMPTY = os.path.join(DATA_DIR, "runtime-policy-empty.json")
POLICY_BOGUS = os.path.join(DATA_DIR, "runtime-policy-bogus.json")


class SignRuntimePolicy_Test(unittest.TestCase):
    def test__get_signer(self):
        # Enable verbose logging, so we see the debug messages.
        Logger().enableVerbose()

        test_cases = [
            {"backend": "", "keyfile": "", "keypath": "", "outcertfile": "", "valid": False},
            {"backend": None, "keyfile": None, "keypath": None, "outcertfile": None, "valid": False},
            {"backend": "x509", "keyfile": "foo", "keypath": "bar", "outcertfile": None, "valid": False},
            {"backend": "ecdsa", "keyfile": EC_PRIVKEY, "keypath": None, "outcertfile": None, "valid": True},
            {"backend": "ecdsa", "keyfile": RSA_PRIVKEY, "keypath": None, "outcertfile": None, "valid": False},
            {
                "backend": "ecdsa",
                "keyfile": EC_PRIVKEY,
                "keypath": "something here",
                "outcertfile": None,
                "valid": False,
            },
            {"backend": "ecdsa", "keyfile": None, "keypath": None, "outcertfile": None, "valid": True},
            {"backend": "x509", "keyfile": None, "keypath": None, "outcertfile": None, "valid": False},
            {"backend": "x509", "keyfile": None, "keypath": None, "outcertfile": "cert.x509", "valid": True},
            {"backend": "x509", "keyfile": EC_PRIVKEY, "keypath": None, "outcertfile": "cert.x509", "valid": True},
            {"backend": "x509", "keyfile": RSA_PRIVKEY, "keypath": None, "outcertfile": "cert.x509", "valid": False},
        ]

        cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                os.chdir(temp_dir)

                for c in test_cases:
                    keypath = None
                    if c["keypath"] is not None and c["keypath"] != "":
                        keypath = os.path.join(temp_dir, c["keypath"])

                    out_certfile = None
                    if c["outcertfile"] is not None and c["outcertfile"] != "":
                        out_certfile = os.path.join(temp_dir, c["outcertfile"])

                    # pylint: disable=protected-access
                    signer = sign_runtime_policy._get_signer(
                        backend=c["backend"],
                        in_ec_keyfile_path=c["keyfile"],
                        out_keyfile_path=keypath,
                        out_certfile=out_certfile,
                    )

                    self.assertEqual(signer is not None, c["valid"])

                    if c["valid"] and keypath:
                        self.assertTrue(os.path.exists(keypath))

                        # Now let us check it is actually an EC privkey.
                        with open(keypath, "rb") as f:
                            pem_data = f.read()
                            key = load_pem_private_key(pem_data, None, default_backend())

                            self.assertTrue(isinstance(key, ec.EllipticCurvePrivateKey))

                    if c["valid"] and out_certfile:
                        self.assertTrue(os.path.exists(out_certfile))

                        # And now we make sure it is a valid x509 cert.
                        with open(out_certfile, "rb") as f:
                            cert_data = f.read()
                            self.assertTrue(is_x509_cert(cert_data))
        finally:
            os.chdir(cwd)

    def test__sign_policy(self):
        # Enable verbose logging, so we see the debug messages.
        Logger().enableVerbose()

        signer_params = [
            {"backend": "ecdsa", "keyfile": EC_PRIVKEY, "keypath": None, "out_certfile": None},
            {"backend": "x509", "keyfile": EC_PRIVKEY, "keypath": None, "out_certfile": "cert.x509"},
        ]

        test_cases = [
            {"policy": "some-non-existing-file", "valid": False},
            {"policy": POLICY_BOGUS, "valid": False},
            {"policy": POLICY_EMPTY, "valid": True},
            {"policy": POLICY, "valid": True},
        ]

        with open(EC_PUBKEY, "rb") as f:
            ec_pubkey = f.read()

        cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                os.chdir(temp_dir)

                signers = {}
                for c in signer_params:
                    # pylint: disable=protected-access
                    signers[c["backend"]] = sign_runtime_policy._get_signer(
                        backend=c["backend"],
                        in_ec_keyfile_path=c["keyfile"],
                        out_keyfile_path=c["keypath"],
                        out_certfile=c["out_certfile"],
                    )

            for c in test_cases:
                for backend, signer in signers.items():
                    # pylint: disable=protected-access
                    signed = sign_runtime_policy._sign_policy(signer, c["policy"])
                    self.assertEqual(signed is not None, c["valid"], msg=f"backend = {backend}, policy = {c['policy']}")

                    # Let's also check that the policy was properly signed.
                    if signed:
                        verified = verify_dsse_envelope(signed.encode("UTF-8"), ec_pubkey)
                        self.assertTrue(verified is not None)
        finally:
            os.chdir(cwd)

    def test_sign_runtime_policy(self):
        # Create an argument parser
        parent_parser = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparser = main_parser.add_subparsers(title="actions")
        parser = sign_runtime_policy.get_arg_parser(subparser, parent_parser)

        test_cases = [
            {"valid": False, "missing_params": True},
            {"--runtime-policy": POLICY, "valid": True, "missing_params": False},
            {
                "--runtime-policy": POLICY,
                "valid": False,
                "--keyfile": "foo",
                "--keypath": "bar",
                "missing_params": False,
            },
            {"--runtime-policy": POLICY, "valid": True, "missing_params": False, "--keyfile": EC_PRIVKEY},
            {"--runtime-policy": POLICY, "valid": False, "missing_params": False, "--keyfile": RSA_PRIVKEY},
        ]

        cwd = os.getcwd()
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                os.chdir(temp_dir)

                for case in test_cases:
                    expected = case["valid"]
                    del case["valid"]
                    missing_params = case["missing_params"]
                    del case["missing_params"]

                    # pylint: disable=consider-using-dict-items
                    cli_args = " ".join(f"{arg} {case[arg]}" for arg in case).split()

                    args = None
                    if missing_params:
                        # When required params are missing, it exits with with SystemExit.
                        with self.assertRaises(SystemExit):
                            args = parser.parse_args(cli_args)
                    else:
                        args = parser.parse_args(cli_args)
                        self.assertTrue(args is not None)

                        signed = sign_runtime_policy.sign_runtime_policy(args)
                        self.assertEqual(signed is not None, expected, msg=f"args = {args}")

        finally:
            os.chdir(cwd)
