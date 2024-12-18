import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from importlib import util
from threading import Thread

from keylime.policy import rpm_repo

_HAS_RPM = util.find_spec("rpm") is not None

HELPER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "create-runtime-policy"))

RPM_DIGESTS = {
    "/usr/bin/dummy-foobar": ["2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"],
    "/etc/dummy-foobar.conf": ["fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"],
}


@contextmanager
def http_server(host: str, port: int, directory: str):
    server = ThreadingHTTPServer((host, port), partial(SimpleHTTPRequestHandler, directory=directory))
    server_thread = Thread(target=server.serve_forever, name="http_server")
    server_thread.start()
    try:
        yield server
    finally:
        server.server_close()
        server.shutdown()
        server_thread.join()


def assertMaplistsEqual(d1, d2, extramsg=""):
    # Ensuring we have only unique values in the digest lists.
    d1_unique = {k: sorted(list(set(v))) for k, v in d1.items()}
    d2_unique = {k: sorted(list(set(v))) for k, v in d2.items()}

    unittest.TestCase().assertEqual(len(d1_unique), len(d2_unique), msg=f"number of files must match {extramsg}")

    for file in d1_unique:
        unittest.TestCase().assertTrue(file in d2_unique)
        unittest.TestCase().assertEqual(
            len(d1_unique[file]), len(d2_unique[file]), msg=f"number of files/digests for {file} {extramsg}"
        )

        for d in d1_unique[file]:
            unittest.TestCase().assertTrue(d in d2_unique[file], msg=f"file={file} digest={d} {extramsg}")


class RpmRepo_Test(unittest.TestCase):
    dirpath = ""

    @classmethod
    def setUpClass(cls):
        cls.dirpath = tempfile.mkdtemp(prefix="keylime-rpm-repo-test")

        setup_script = os.path.abspath(os.path.join(HELPER_DIR, "setup-rpm-tests"))

        result = subprocess.run(
            [setup_script, cls.dirpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
        print("STDOUT:", result.stdout.decode("UTF-8"), file=sys.stderr)
        print("STDERR:", result.stderr.decode("UTF-8"), file=sys.stderr)
        RpmRepo_Test().assertEqual(result.returncode, 0)

    @classmethod
    def tearDownClass(cls):
        if cls.dirpath is not None:
            shutil.rmtree(cls.dirpath)

    def test_analyze_local_repo(self):
        test_cases = [
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-ecc"),
                "valid": True,
                "hashes": RPM_DIGESTS,
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-rsa"),
                "valid": True,
                "hashes": RPM_DIGESTS,
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "unsigned"),
                "valid": True,
                "hashes": RPM_DIGESTS,
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-mismatch"),
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "no-repomd"),
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-no-key"),
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            },
            {
                "repo": "",
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            },
            {
                "repo": "foo/bar/",
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            },
        ]

        for c in test_cases:
            hashes, _ima_sig, ok = rpm_repo.analyze_local_repo(c["repo"])
            self.assertEqual(ok, c["valid"], msg=f"repo = {c['repo']}")
            self.assertEqual(hashes, c["hashes"], msg=f"repo = {c['repo']}")
            # TODO: verify the ima_sig.

    def test_analyze_rpm_pkg(self):
        test_cases = [
            {
                "rpm": os.path.join(self.dirpath, "repo", "unsigned", "DUMMY-empty-42.0.0-el42.noarch.rpm"),
                "hashes": {},
                "ima-sig": {},
            },
            {
                "rpm": os.path.join(self.dirpath, "repo", "signed-rsa", "DUMMY-empty-42.0.0-el42.noarch.rpm"),
                "hashes": {},
                "ima-sig": {},  # FIXME
            },
            {
                "rpm": os.path.join(self.dirpath, "repo", "signed-rsa", "DUMMY-foo-42.0.0-el42.noarch.rpm"),
                "hashes": RPM_DIGESTS,
                "ima-sig": {},
            },
        ]

        for c in test_cases:
            hashes, _ima_sig = rpm_repo.analyze_rpm_pkg(pathlib.Path(c["rpm"]))
            self.assertEqual(hashes, c["hashes"], msg=f"rpm = {c['rpm']}")
            # TODO: verify ima-sig.

    def test__analyze_remote_repo(self):
        test_cases = [
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-ecc"),
                "valid": True,
                "hashes": RPM_DIGESTS,
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-rsa"),
                "valid": True,
                "hashes": RPM_DIGESTS,
                "ima-sig": {},  # FIXME
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "unsigned"),
                "valid": True,
                "hashes": RPM_DIGESTS,
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-mismatch"),
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "no-repomd"),
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-no-key"),
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            },
        ]

        # Let us test also for filelists-ext mismatch, in case createrepo_c
        # supports it -- if it does, the respective test directory will exist.
        fext_dir = os.path.join(self.dirpath, "repo", "filelist-ext-mismatch")
        if os.path.isdir(fext_dir):
            fext_test_case = {
                "repo": fext_dir,
                "valid": False,
                "hashes": {},
                "ima-sig": {},
            }
            test_cases.append(fext_test_case)

        for c in test_cases:
            with http_server("localhost", 0, c["repo"]) as httpd:
                url = f"http://localhost:{httpd.server_port}"
                digests, _ima_sig, ok = rpm_repo.analyze_remote_repo(url)
                assertMaplistsEqual(digests, c["hashes"], c["repo"])
                self.assertEqual(ok, c["valid"])
                # TODO: test the IMA signatures.

        # Now let us test a repo using unsupported (i.e. != gzip)
        # compression.
        unsupported_comp = os.path.join(self.dirpath, "repo", "unsupported-compression")
        with http_server("localhost", 0, unsupported_comp) as httpd:
            url = f"http://localhost:{httpd.server_port}"
            self.assertRaises(Exception, rpm_repo._analyze_remote_repo, url)  # pylint: disable=protected-access

            # The public method does not raise an exception.
            digests, _imasigs, ok = rpm_repo.analyze_remote_repo(url)
            self.assertFalse(ok, msg=f"repo = {unsupported_comp}")
            self.assertEqual(digests, {})

    def test_analyze_rpm_pkg_url(self):
        test_cases = [
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-rsa"),
                "rpm": "DUMMY-bar-42.0.0-el42.noarch.rpm",
                "hashes": RPM_DIGESTS,
                "ima-sig": {},  # FIXME
            },
            {
                "repo": os.path.join(self.dirpath, "repo", "signed-rsa"),
                "rpm": "DUMMY-empty-42.0.0-el42.noarch.rpm",
                "hashes": {},
                "ima-sig": {},
            },
            {"repo": os.path.join(self.dirpath, "repo", "signed-rsa"), "rpm": "foo/bar", "hashes": {}, "ima-sig": {}},
        ]

        for c in test_cases:
            with http_server("localhost", 0, c["repo"]) as httpd:
                url = f"http://localhost:{httpd.server_port}/{c['rpm']}"
                digests, _ima_sig = rpm_repo.analyze_rpm_pkg_url(url)
                assertMaplistsEqual(digests, c["hashes"])
                # TODO: test the IMA signatures.
