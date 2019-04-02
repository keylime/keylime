import unittest
import os
import sys

# Useful constants for the test
KEYLIME_DIR=os.getcwd()+"/../keylime/"

# Custom imports
sys.path.insert(0, KEYLIME_DIR)
from ca_impl_openssl import *


class OpenSSL_Test(unittest.TestCase):
    
    def test_openssl(self):
        _ = mk_cacert("my ca")
        (ca_cert, ca_pk, _) = mk_cacert()
        cert,_ = mk_signed_cert(ca_cert, ca_pk, "cert", 4)
        
        self.assertTrue(cert.verify(ca_cert.get_pubkey()))


if __name__ == '__main__':
    unittest.main()
