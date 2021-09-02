'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Red Hat, Inc.
'''


import unittest
import sys
from pathlib import Path
import shutil

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.asymmetric import padding

from keylime import ca_impl_cfssl

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
CODE_ROOT = (f"{PACKAGE_ROOT}/keylime/")

# Custom imports
sys.path.insert(0, CODE_ROOT)


class CFSSL_Test(unittest.TestCase):

    @unittest.skipIf(shutil.which("cfssl") is None, "cfssl was not found in the PATH")
    def test_cfssl(self):
        _ = ca_impl_cfssl.mk_cacert("my ca")
        (ca_cert, ca_pk, _) = ca_impl_cfssl.mk_cacert()
        cert, _ = ca_impl_cfssl.mk_signed_cert(ca_cert, ca_pk, "cert", _)

        pubkey = ca_cert.public_key()
        try:
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except crypto_exceptions.InvalidSignature:
            self.fail("Certificate signature validation failed.")

if __name__ == '__main__':
    unittest.main()
