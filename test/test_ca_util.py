"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Red Hat, Inc.
"""


import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from keylime import ca_util

# Useful constants for the test
PACKAGE_ROOT = Path(__file__).parents[1]
CODE_ROOT = f"{PACKAGE_ROOT}/keylime/"

# Custom imports
sys.path.insert(0, CODE_ROOT)


class CA_Util_Test(unittest.TestCase):
    def test_load_cert_by_path(self):
        curdir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(curdir, "data", "ca", "cacert.crt")
        cert = ca_util.load_cert_by_path(cert_path)

        self.assertEqual(cert.serial_number, 1)

    def test_get_crl_distpoint(self):
        curdir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(curdir, "data", "ca", "cacert.crt")

        crl_distpoint = ca_util.get_crl_distpoint(cert_path)
        self.assertEqual(crl_distpoint, "http://localhost/crl.pem")

    def test_ca_util(self):
        ca_util.setpassword("42")

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

            # cmd_regencrl()
            ca_util.cmd_regencrl(working_dir)
        except Exception as e:
            self.fail(e)
        finally:
            # Remove temporary directory.
            shutil.rmtree(working_dir)
