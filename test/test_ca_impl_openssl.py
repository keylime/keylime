import unittest
import os
import sys
from pathlib import Path

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
CODE_ROOT = (f"{PACKAGE_ROOT}/keylime/")

# Custom imports
sys.path.insert(0, CODE_ROOT)
from keylime import ca_impl_openssl


class OpenSSL_Test(unittest.TestCase):

    def test_openssl(self):
        _ = ca_impl_openssl.mk_cacert("my ca")
        (ca_cert, ca_pk, _) = ca_impl_openssl.mk_cacert()
        cert,_ = ca_impl_openssl.mk_signed_cert(ca_cert, ca_pk, "cert", 4)

        self.assertTrue(cert.verify(ca_cert.get_pubkey()))


if __name__ == '__main__':
    unittest.main()
