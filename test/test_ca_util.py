import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from keylime import ca_util, fs_util

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
CODE_ROOT = f"{PACKAGE_ROOT}/keylime/"

# Custom imports
sys.path.insert(0, CODE_ROOT)

# ca_util delegates certificate generation to ca_impl_openssl, whose mk_cacert()
# needs a valid "ca" config section. Set it via the KEYLIME_CA_* environment
# override so the module doesn't depend on a system-installed /etc/keylime/ca.conf.
CA_TEST_ENV = {
    "KEYLIME_CA_CERT_BITS": "2048",
    "KEYLIME_CA_CERT_COUNTRY": "US",
    "KEYLIME_CA_CERT_CA_LIFETIME": "3650",
    "KEYLIME_CA_CERT_CRL_DIST": "http://localhost:38080/crl",
}

_env_patcher = None


def setUpModule() -> None:
    global _env_patcher
    _env_patcher = mock.patch.dict(os.environ, CA_TEST_ENV)
    _env_patcher.start()


def tearDownModule() -> None:
    assert _env_patcher is not None
    _env_patcher.stop()


class CA_Util_Test(unittest.TestCase):
    def test_load_cert_by_path(self):
        curdir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(curdir, "data", "ca", "cacert.crt")
        cert = ca_util.load_cert_by_path(cert_path)

        self.assertEqual(cert.serial_number, 1)

    def test_ca_util(self):
        ca_util.read_password("42")

        # Create directory to be our working dir.
        working_dir = tempfile.mkdtemp()
        assert working_dir
        try:
            # cmd_init()
            ca_util.cmd_init(working_dir)

            # cmd_mkcert()
            ca_util.cmd_mkcert(working_dir, "foo bar")

            # cmd_certpkg()
            ca_util.cmd_certpkg(working_dir, "foo bar")

            # cmd_revoke()
            ca_util.cmd_revoke(working_dir, "foo bar")
        except Exception as e:
            self.fail(e)
        finally:
            # Remove temporary directory.
            shutil.rmtree(working_dir)

    def test_ca_import_priv_classic(self):
        curdir = os.path.dirname(os.path.abspath(__file__))
        keydir = os.path.join(curdir, "data", "ima_keys")
        ca_util.read_password("42")
        # Create directory to be our working dir.
        working_dir = tempfile.mkdtemp()
        assert working_dir
        try:
            fs_util.ch_dir(working_dir)
            ca_util.cmd_import_priv(working_dir, os.path.join(keydir, "rsa2048.pem"), 3)
            priv = ca_util.read_private(False)
            load_pem_private_key(bytes(priv[0]["ca"]), None, default_backend())
        except Exception as e:
            self.fail(e)
        finally:
            # Remove temporary directory.
            shutil.rmtree(working_dir)
            fs_util.ch_dir(curdir)

    def test_ca_import_priv_pkcs8(self):
        curdir = os.path.dirname(os.path.abspath(__file__))
        key = os.path.join(curdir, "data", "ca-private.pem")
        ca_util.read_password("42")
        # Create directory to be our working dir.
        working_dir = tempfile.mkdtemp()
        assert working_dir
        try:
            fs_util.ch_dir(working_dir)
            ca_util.cmd_import_priv(working_dir, key, 2)
            priv = ca_util.read_private(False)
            load_pem_private_key(bytes(priv[0]["ca"]), None, default_backend())
        except Exception as e:
            self.fail(e)
        finally:
            # Remove temporary directory.
            shutil.rmtree(working_dir)
            fs_util.ch_dir(curdir)
