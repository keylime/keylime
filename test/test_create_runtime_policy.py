import argparse
import copy
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from importlib import util
from test.utils import assertDigestsEqual, keylimePolicyAssertLogs

from keylime.common import algorithms
from keylime.ima import ima
from keylime.policy import create_runtime_policy, initrd
from keylime.policy.logger import Logger

_HAS_LIBARCHIVE = util.find_spec("libarchive") is not None

HELPER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "create-runtime-policy"))

# The test initrds have the following content.
INITRD_LEGACY_ALLOWLIST = """18eb0ba043d6fc5b06b6f785b4a411fa0d6d695c4a08d2497e8b07c4043048f7  /usr/bin/foo
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /usr/lib/foobar.so
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /usr/lib64/foobar64.so
dd2ccf6ebfabbca501864a3ec5aebecfadd69d717ea9d9ddd509b49471d039db  /usr/sbin/bar
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /dev/foo bar
"""

INITRD_DIGESTS_SHA256 = {
    "/dev/foo_bar": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    "/usr/bin/foo": ["18eb0ba043d6fc5b06b6f785b4a411fa0d6d695c4a08d2497e8b07c4043048f7"],
    "/usr/lib/foobar.so": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    "/usr/lib64/foobar64.so": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    "/usr/sbin/bar": ["dd2ccf6ebfabbca501864a3ec5aebecfadd69d717ea9d9ddd509b49471d039db"],
}

INITRD_DIGESTS_SHA1 = {
    "/dev/foo_bar": ["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
    "/usr/bin/foo": ["a26ce416a048883cd6ca8e890f6b0a62a8031e8a"],
    "/usr/lib/foobar.so": ["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
    "/usr/lib64/foobar64.so": ["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
    "/usr/sbin/bar": ["ec6705ccdaafdf57261e35e40379cc339d36a204"],
}


EXCLUDE_LIST = """
boot_aggregate
/usr/sbin/bar
/dev/foo bar
"""


class CreateRuntimePolicy_Test(unittest.TestCase):
    dirpath = ""
    logger = Logger()

    @classmethod
    def setUpClass(cls):
        cls.dirpath = tempfile.mkdtemp(prefix="keylime-create-runtime-policy-test")

        setup_script = os.path.abspath(os.path.join(HELPER_DIR, "setup-initrd-tests"))

        result = subprocess.run(
            [setup_script, cls.dirpath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        print("STDOUT:", result.stdout.decode("UTF-8"), file=sys.stderr)
        print("STDERR:", result.stderr.decode("UTF-8"), file=sys.stderr)
        CreateRuntimePolicy_Test().assertEqual(result.returncode, 0)

    @classmethod
    def tearDownClass(cls):
        if cls.dirpath is not None:
            shutil.rmtree(cls.dirpath)

    def test_InitrdReader(self):
        initrd_dir = os.path.join(self.dirpath, "initrd")
        for initrd_file in create_runtime_policy.list_initrds(basedir=initrd_dir):
            ii = initrd.InitrdReader(initrd_file)
            digests = create_runtime_policy.path_digests(ii.contents(), remove_prefix=True)

            # Now let's validate the digests.
            assertDigestsEqual(digests, INITRD_DIGESTS_SHA256)

    @unittest.skipUnless(_HAS_LIBARCHIVE, "libarchive not available")
    def test_InitrdReader_extract_at_offset_methods(self):
        initrd_dir = os.path.join(self.dirpath, "initrd")

        libarchive_digests = None
        fallback_digests = None
        cwd = os.getcwd()

        for initrd_file in create_runtime_policy.list_initrds(basedir=initrd_dir):
            with open(initrd_file, "rb") as infile:
                offset = initrd.InitrdReader.skip_cpio(infile)

                with tempfile.TemporaryDirectory() as libarchive_dir:
                    os.chdir(libarchive_dir)
                    try:
                        initrd.InitrdReader.extract_at_offset_libarchive(infile, offset)
                        digests = create_runtime_policy.path_digests(libarchive_dir, remove_prefix=True)
                        if libarchive_digests is None:
                            libarchive_digests = digests
                        assertDigestsEqual(digests, libarchive_digests)
                    except Exception as e:
                        self.fail(f"No exception expected while testing libarchive extraction: {e}")
                    finally:
                        os.chdir(cwd)

                with tempfile.TemporaryDirectory() as fallback_dir:
                    os.chdir(fallback_dir)
                    try:
                        initrd.InitrdReader.extract_at_offset_fallback(infile, offset)
                        digests = create_runtime_policy.path_digests(fallback_dir, remove_prefix=True)
                        if fallback_digests is None:
                            fallback_digests = digests
                        assertDigestsEqual(digests, fallback_digests)
                    except Exception as e:
                        self.fail(f"No exception expected while testing fallback extraction: {e}")
                    finally:
                        os.chdir(cwd)

        # Finally, let's make sure the result of libarchive and the fallback
        # method are the same.
        assertDigestsEqual(libarchive_digests, fallback_digests)

        # Now let's check a "bad" file.
        bad_file = os.path.abspath(os.path.join(HELPER_DIR, "setup-initrd-tests"))
        with open(bad_file, "rb") as infile:
            self.assertRaises(
                Exception,
                initrd.InitrdReader.extract_at_offset_libarchive,
                infile,
                0,
            )
            self.assertRaises(
                Exception,
                initrd.InitrdReader.extract_at_offset_fallback,
                infile,
                0,
            )

    def test_boot_aggregate(self):
        test_cases = [
            {"input": "", "boot_aggregate": "", "alg": "invalid"},
            {
                "input": "10 0000000000000000000000000000000000000000 ima 0000000000000000000000000000000000000000 boot_aggregate",
                "boot_aggregate": "0000000000000000000000000000000000000000",
                "alg": "sha1",
            },
            {
                "input": "10 0000000000000000000000000000000000000000 ima a00000000000000000000000000000000000000b boot_aggregate",
                "boot_aggregate": "a00000000000000000000000000000000000000b",
                "alg": "sha1",
            },
            {
                "input": "10 0000000000000000000000000000000000000000 ima a00000000000000000000000000000000000000bcc boot_aggregate",
                "boot_aggregate": "",
                "alg": "invalid",
            },
            {
                "input": "FOO BAR",
                "boot_aggregate": "",
                "alg": "invalid",
            },
            {
                "input": "10 8d814e778e1fca7c551276523ac44455da1dc420 ima-ng sha256:0bc72531a41dbecb38557df75af4bc194e441e71dc677c659a1b179ac9b3e6ba boot_aggregate",
                "boot_aggregate": "0bc72531a41dbecb38557df75af4bc194e441e71dc677c659a1b179ac9b3e6ba",
                "alg": "sha256",
            },
            {
                "input": "10 8d814e778e1fca7c551276523ac44455da1dc420 ima-ng sha1:0bc72531a41dbecb38557df75af4bc194e441e71dc677c659a1b179ac9b3e6ba boot_aggregate",
                "boot_aggregate": "",
                "alg": "invalid",
            },
            {
                "input": "10 8d814e778e1fca7c551276523ac44455da1dc420 ima-ng unknown:0bc72531a41dbecb38557df75af4bc194e441e71dc677c659a1b179ac9b3e6ba boot_aggregate",
                "boot_aggregate": "",
                "alg": "invalid",
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            agg_file = os.path.join(tmpdir, "measurements")
            for c in test_cases:
                alg, aggregate = create_runtime_policy.boot_aggregate_parse(c["input"])
                self.assertEqual(alg, c["alg"], msg=f"alg={alg}, digest={aggregate}")
                self.assertEqual(aggregate, c["boot_aggregate"])

                # Now parsing it from a file.
                with open(agg_file, "w", encoding="UTF-8") as mfile:
                    mfile.write(c["input"])

                alg, aggregate = create_runtime_policy.boot_aggregate_from_file(agg_file)
                self.assertEqual(alg, c["alg"], msg=f"{c['input']}")
                self.assertEqual(aggregate, c["boot_aggregate"])

        # Now let's parse some bogus entries.
        # These should throw an exception.
        bad_entries = [
            "pcr pcr-value img-ng sha999:fff boot_aggregate",
            "pcr pcr-value img-ng sha1:fff boot_aggregate",
            "pcr pcr-value img-ng sha256:fff boot_aggregate",
            "pcr pcr-value ima fff boot_aggregate",
        ]
        for line in bad_entries:
            alg, aggregate = create_runtime_policy.boot_aggregate_parse(line)
            self.assertEqual(alg, "invalid", msg=f"line = {line}")
            self.assertEqual(aggregate, "", msg=f"line = {line}")

    def test_file_digest(self):
        initrd_file = os.path.join(self.dirpath, "initrd", "initramfs-keylime-fedora-cat.img")
        r = initrd.InitrdReader(initrd_file)

        file_path = os.path.join(r.contents(), "usr/bin/foo")
        test_cases = [
            {
                "file": file_path,
                "alg": "sha1",
                "digest": "a26ce416a048883cd6ca8e890f6b0a62a8031e8a",
            },
            {
                "file": file_path,
                "alg": "sha384",
                "digest": "d2fcda9b029aa42f511b2d954e4bebaff2f4f6431374c111ec8efa59204c74164491e14e43e144a3b18e98bf6043cf75",
            },
            {
                "file": file_path,
                "alg": "sha512",
                "digest": "2f979b08be70d85814d56ff5e21628ab79de93e1e88facdb975c71237ea46c47afc61d39d2eb089a4f7e5faafc05d5c11ee38db9c65167ac22b8cc4ad89f080c",
            },
        ]

        for c in test_cases:
            self.assertTrue(algorithms.Hash.is_recognized(c["alg"]))
            self.assertEqual(
                algorithms.Hash(c["alg"]).file_digest(c["file"]),
                c["digest"],
            )

    def test_get_initrds_digests(self):
        initrd_dir = os.path.join(self.dirpath, "initrd")
        test_cases = [
            {
                "algo": "sha1",
                "expected": INITRD_DIGESTS_SHA1,
            },
            {
                "algo": "sha256",
                "expected": INITRD_DIGESTS_SHA256,
            },
        ]

        for c in test_cases:
            digests = create_runtime_policy.get_initrds_digests(initrd_dir, {}, c["algo"])
            assertDigestsEqual(digests, c["expected"])

    def test_process_flat_allowlist(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            allowlist = os.path.join(tmpdir, "allowlist")
            with open(allowlist, "w", encoding="UTF-8") as mfile:
                mfile.write(INITRD_LEGACY_ALLOWLIST)

            digests, ok = create_runtime_policy.process_flat_allowlist(allowlist, {})
            self.assertTrue(ok)
            assertDigestsEqual(digests, INITRD_DIGESTS_SHA256)

            malformed_allowlist = """checksum file oops
#
checksum-2
checksum-3 foo bar file 01
checksum-4 \
         bar foo file 02




"""
            with open(allowlist, "w", encoding="UTF-8") as mfile:
                mfile.write(malformed_allowlist)
            digests, ok = create_runtime_policy.process_flat_allowlist(allowlist, {})
            self.assertTrue(ok)
            # 3 valid entries there, with some lines skipped:
            # file oops -> with checksum: checksum
            # foo bar file 01 -> with checksum: checksum-3
            # bar foo file 02 -> with checksum: checksum-4
            self.assertEqual(len(digests), 3)

            # Now let's test some invalid file.
            digests, ok = create_runtime_policy.process_flat_allowlist("/some/invalid/non/existing/file/here", {})
            self.assertFalse(ok)
            self.assertEqual(len(digests), 0)

    def test_path_digest_owned_by_root(self):
        homedir = os.path.join(self.dirpath, "dummy-rootfs", "home")
        fpath = os.path.join("/", "foobar", "non-root")  # homedir becomes the rootfs "/"

        test_cases = [
            {
                "path": [fpath],
                "checksum": {fpath: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},
                "algo": "sha256",
                "owned_by_root": False,
            },
            {"path": [], "checksum": {}, "algo": "sha256", "owned_by_root": True},
        ]

        for c in test_cases:
            digests = create_runtime_policy.path_digests(homedir, alg=c["algo"], only_owned_by_root=c["owned_by_root"])
            self.assertEqual(len(digests), len(c["path"]))
            for ff in digests:
                self.assertTrue(ff in c["path"])
            assertDigestsEqual(digests, c["checksum"])

    def test_rootfs_absolute_path(self):
        homedir = os.path.join(self.dirpath, "dummy-rootfs", "home")
        digests = create_runtime_policy.path_digests(homedir)
        for ff in digests:
            self.assertFalse(pathlib.PurePath(ff).is_relative_to(homedir))

    def test_path_digest_dirs_to_exclude(self):
        rootfsdir = os.path.join(self.dirpath, "dummy-rootfs")
        homedir = os.path.join(rootfsdir, "home")

        digests = create_runtime_policy.path_digests(homedir)
        self.assertEqual(len(digests), 1, msg=f"digests = {digests}")

        digests = create_runtime_policy.path_digests(homedir, dirs_to_exclude=None)
        self.assertEqual(len(digests), 1, msg=f"digests={digests}, dirs_to_exclude=None")

        digests = create_runtime_policy.path_digests(homedir, dirs_to_exclude=[])
        self.assertEqual(len(digests), 1, msg=f"digests = {digests}, dirs_to_exclude=[]")

        digests = create_runtime_policy.path_digests(homedir, dirs_to_exclude=["/foobar"])
        self.assertEqual(len(digests), 0, msg=f"digests = {digests}, dirs_to_exclude=['/foobar']")

        digests = create_runtime_policy.path_digests(homedir, dirs_to_exclude=["/non-existing"])
        self.assertEqual(len(digests), 1, msg=f"digests = {digests}, dirs_to_exclude=['/non-existing']")

    def test_process_exclude_list(self):
        test_cases = [
            {
                "line": "boot_aggregate",
                "valid": True,
            },
            {
                "line": "boot.aggreg*$",
                "valid": True,
            },
            {
                "line": "*",
                "valid": False,
            },
            {
                "line": "foobar.so(.*)?",
                "valid": True,
            },
            {
                "line": "",
                "valid": True,
            },
        ]

        for c in test_cases:
            _, ok = create_runtime_policy.process_exclude_list_line(c["line"])
            self.assertEqual(ok, c["valid"])

        test_cases = [
            {
                "lines": """boot_aggregate
boot.aggreg*$
*
foobar.so(.*)?

""",
                "expected": [],
                "valid": False,
            },
            {
                "lines": """boot_aggregate
boot.aggreg*$
foobar.so(.*)?
""",
                "expected": ["boot_aggregate", "boot.aggreg*$", "foobar.so(.*)?"],
                "valid": True,
            },
            {
                "lines": """


""",
                "expected": [],
                "valid": True,
            },
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            excludelist = os.path.join(tmpdir, "excludelist")
            for c in test_cases:
                with open(excludelist, "w", encoding="UTF-8") as mfile:
                    mfile.write(c["lines"])

                exclude, ok = create_runtime_policy.process_exclude_list_file(excludelist, [])
                self.assertEqual(ok, c["valid"], msg=f"lines = {c['lines']}")
                self.assertEqual(sorted(c["expected"]), sorted(exclude), msg=f"lines = {c['lines']}")

        # Now let's test some invalid file.
        exclude, ok = create_runtime_policy.process_exclude_list_file("/some/invalid/non/existing/file/here", [])
        self.assertFalse(ok)
        self.assertEqual(len(exclude), 0)

    def test_merge_lists(self):
        test_cases = [
            {
                "a": [],
                "b": [],
                "expected": [],
            },
            {
                "a": ["a"],
                "b": [],
                "expected": ["a"],
            },
            {
                "a": [],
                "b": ["b"],
                "expected": ["b"],
            },
            {
                "a": ["a"],
                "b": ["a"],
                "expected": ["a"],
            },
            {
                "a": ["a", "b"],
                "b": ["b"],
                "expected": ["a", "b"],
            },
            {
                "a": ["a", "b", "c"],
                "b": ["b", "e"],
                "expected": ["a", "b", "c", "e"],
            },
        ]

        for c in test_cases:
            self.assertEqual(create_runtime_policy.merge_lists(c["a"], c["b"]), c["expected"])

    def test_merge_maplists(self):
        test_cases = [
            {
                "a": {},
                "b": {},
                "expected": {},
            },
            {"a": {}, "b": {"file": ["checksum"]}, "expected": {"file": ["checksum"]}},
            {"a": {"file": ["checksum"]}, "b": {}, "expected": {"file": ["checksum"]}},
            {
                "a": {"file": ["checksum"]},
                "b": {"file": ["checksum"]},
                "expected": {"file": ["checksum"]},
            },
            {
                "a": {"file": ["checksum-1"]},
                "b": {"file": ["checksum-2"]},
                "expected": {"file": ["checksum-1", "checksum-2"]},
            },
            {
                "a": {"file": ["checksum-1", "checksum-2", "checksum-3"]},
                "b": {"file": ["checksum-2"], "file-2": ["checksum-4"]},
                "expected": {
                    "file": ["checksum-1", "checksum-2", "checksum-3"],
                    "file-2": ["checksum-4"],
                },
            },
        ]
        for c in test_cases:
            self.assertEqual(create_runtime_policy.merge_maplists(c["a"], c["b"]), c["expected"])

    def test_get_hashes_from_measurement_list(self):
        test_cases = [
            {
                "ima-list": """

""",
                "expected": {},
                "valid": True,
            },
            {
                "ima-list": """10 0adefe762c149c7cec19da62f0da1297fcfbffff ima-ng sha256:0000000000000000000000000000000000000000000000000000000000000000 boot_aggregate
10 cff3da2ff339a1f07bb0dbcbc0381e794ed09555 ima-ng sha256:3e5e8ad9d8b4dd191413aba6166c7a975c3eab903d1fad77ecfa2d5810d6585c /usr/bin/kmod
10 13d5b414e08a45698ce9e3c66545b25ba694046c ima-ng sha256:f51de8688a2903b94016c06f186cf1f053ececd2a88a5f349f29b35a06e94c43 /usr/lib64/ld-linux-x86-64.so.2
""",
                "expected": {
                    "boot_aggregate": ["0000000000000000000000000000000000000000000000000000000000000000"],
                    "/usr/bin/kmod": ["3e5e8ad9d8b4dd191413aba6166c7a975c3eab903d1fad77ecfa2d5810d6585c"],
                    "/usr/lib64/ld-linux-x86-64.so.2": [
                        "f51de8688a2903b94016c06f186cf1f053ececd2a88a5f349f29b35a06e94c43"
                    ],
                },
                "valid": True,
            },
            {
                "ima-list": "",
                "expected": {},
                "valid": True,
            },
            {
                "ima-list": "10 cff3da2ff339a1f07bb0dbcbc0381e794ed09555 ima-ng sha256:3e5e8ad9d8b4dd191413aba6166c7a975c3eab903d1fad77ecfa2d5810d6585c",
                "expected": {},
                "valid": True,
            },
            {
                "ima-list": "10 6f3474e730fb7da4bb26cad2d8f5d9d5482735f6 ima-buf sha256:571016c9f57363c80e08dd4346391c4e70227e41b0247b8a3aa2240a178d3d14 dm_table_load 646d5f76657273696f6e3d342e34362e303b6e616d653d7268656c2d726f6f742c757569643d4c564d2d79543538654c3268616470746a55396c565131573078315035544679454e35627450416b375963386779586633446667647a6a7554466b4a39503661746868582c6d616a6f723d3235332c6d696e6f723d302c6d696e6f725f636f756e743d312c6e756d5f746172676574733d313b7461726765745f696e6465783d302c7461726765745f626567696e3d302c7461726765745f6c656e3d3133333133363338342c7461726765745f6e616d653d6c696e6561722c7461726765745f76657273696f6e3d312e342e302c6465766963655f6e616d653d3235323a332c73746172743d37333234363732303b",
                "expected": {},
                "valid": True,
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            ima_list = os.path.join(tmpdir, "ascii_runtime_measurements")
            for c in test_cases:
                with open(ima_list, "w", encoding="UTF-8") as mfile:
                    mfile.write(c["ima-list"])

                hashes, ok = create_runtime_policy.get_hashes_from_measurement_list(ima_list, {})
                self.assertEqual(ok, c["valid"], msg=f"ima-list: ({c['ima-list']})")
                print("HASHES", hashes)
                self.assertEqual(hashes, c["expected"], msg=f"ima-list: ({c['ima-list']})")

        # Try non-existing file.
        hashes, ok = create_runtime_policy.get_hashes_from_measurement_list(
            "/some/invalid/non/existing/ima/list/here", {}
        )
        self.assertFalse(ok)
        self.assertEqual(len(hashes), 0)

    def test_update_base_policy(self):
        # TODO: add now some actual good cases, to test the more
        # important flow.
        # XXX: Need to clarify whether "verification-keys" is correct
        # being a single string instead of an array of strings.
        test_cases = [
            # Base policy is an invalid JSON
            {
                "base-policy": "not-valid-json",
                "expected": None,
            },
            # Base policy is a valid JSON with a field matching the current
            # format, but with an invalid content according to current schema
            {
                "base-policy": '{"valid": "json", "verification-keys": "invalid"}',
                "expected": None,
            },
            # Base policy is a valid JSON without any matching field against the
            # current schema
            {
                "base-policy": '{"valid": "json", "invalid": "policy"}',
                "expected": ima.empty_policy(),
            },
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            base_policy = os.path.join(tmpdir, "base-policy")
            for c in test_cases:
                with open(base_policy, "w", encoding="UTF-8") as mfile:
                    mfile.write(c["base-policy"])

                policy = create_runtime_policy.update_base_policy(base_policy)
                self.assertEqual(policy, c["expected"])

        # Try non-existing file.
        policy = create_runtime_policy.update_base_policy("/some/invalid/non/existing/policy/here")
        self.assertEqual(policy, None)

    def test_get_digest_algorithm_from_hex(self):
        """Test that the algorithm guessing works as expected"""

        test_cases = [
            {
                "digest": "0001020304050607080900010203040506070809",
                "expected_algorithm": "sha1",
            },
            {
                "digest": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "expected_algorithm": "sha256",
            },
            {
                "digest": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
                "expected_algorithm": "sha384",
            },
            {
                "digest": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                "expected_algorithm": "sha512",
            },
            {
                "digest": "0001020304050607080900",
                "expected_algorithm": "invalid",
            },
        ]

        for case in test_cases:
            algorithm = create_runtime_policy._get_digest_algorithm_from_hex(  # pylint: disable=protected-access
                case["digest"]
            )
            self.assertEqual(algorithm, case["expected_algorithm"])

    def test_get_digest_algorithm_from_map_list(self):
        """Test that the algorithm guessing works as expected"""

        test_cases = [
            {
                "digests": {"key": ["0001020304050607080900010203040506070809"]},
                "expected_algorithm": "sha1",
            },
            {
                "digests": {"key": ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"]},
                "expected_algorithm": "sha256",
            },
            {
                "digests": {
                    "key": [
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
                    ]
                },
                "expected_algorithm": "sha384",
            },
            {
                "digests": {
                    "key": [
                        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                    ]
                },
                "expected_algorithm": "sha512",
            },
            {
                "digests": {"key": ["0001020304050607080900"]},
                "expected_algorithm": "invalid",
            },
        ]

        for case in test_cases:
            algorithm = create_runtime_policy._get_digest_algorithm_from_map_list(  # pylint: disable=protected-access
                case["digests"]
            )
            self.assertEqual(algorithm, case["expected_algorithm"])

    def test_rootfs_with_symbolic_links(self):
        test_cases = [
            # Test that symlinks and files in the excluded directory are ignored
            {
                "dirs": ["root", "root/excluded", "root/included", "root/included/nested_excluded"],
                "files": ["root/a", "root/included/b", "root/excluded/c", "root/included/nested_excluded/d", "outside"],
                "symlinks": [
                    ("root/sa", "root/a"),
                    ("root/sb", "root/excluded/c"),
                    ("root/sc", "outside"),
                    ("root/sd", "root/included/nested_excluded/d"),
                ],
                "root": "root",
                "dirs_to_exclude": ["/excluded", "/included/nested_excluded"],
                "algorithm": "sha256",
                "expected_out": {
                    "/a": ["f86309c6fecb020efe59a73666162b69e43035da434c7c92df293553810e9907"],
                    "/included/b": ["5b5b4bcb3b77ca3017d9f3ff9424f777389116c70e4b57c88a3ee857182a3d43"],
                },
            },
        ]

        for case in test_cases:
            with tempfile.TemporaryDirectory() as tmpdir:
                for d in case["dirs"]:
                    os.makedirs(os.path.join(tmpdir, d))

                for f in case["files"]:
                    with open(os.path.join(tmpdir, f), "w", encoding="UTF-8") as fd:
                        fd.write(f"some content in {f}")

                for symlink, target in case["symlinks"]:
                    os.symlink(os.path.join(tmpdir, target), os.path.join(tmpdir, symlink))

                digests = create_runtime_policy.path_digests(
                    os.path.join(tmpdir, case["root"]),
                    alg=case["algorithm"],
                    dirs_to_exclude=case["dirs_to_exclude"],
                )

                self.assertEqual(digests, case["expected_out"])

    def test_digest_algorithm_priority(self):
        """Test that the priority for the algorithm selection follows the
        expected source order: --algo option > base policy > allowlist > ima log"""

        test_cases = []

        rootfs = os.path.join(HELPER_DIR, "rootfs")
        # Prepare test cases
        for algo in ["sha1", "sha256", "sha384", "sha512", "sm3_256"]:
            base_policy = os.path.join(HELPER_DIR, f"policy-{algo}")
            allowlist = os.path.join(HELPER_DIR, f"allowlist-{algo}")
            ima_log = os.path.join(HELPER_DIR, f"ima-log-{algo}")

            # Case where the algorithm from the IMA measurement list should be
            # kept
            test_cases.append(
                {
                    "algo_opt": [],
                    "base_policy": [],
                    "allowlist": [],
                    "ima_log": ["--ima-measurement-list", ima_log],
                    "rootfs": [],
                    "expected_algo": f"{algo}",
                    "expected_source": "IMA measurement list",
                }
            )

            # Cases where the algorithm from the allowlist should be kept
            for il in [[], ["--ima-measurement-list", ima_log]]:
                for rfs in [[], ["--rootfs", rootfs]]:
                    # Skip the exceptional cases when the algorithm from the
                    # allowlist is ambiguous
                    if algo not in [algorithms.Hash.SHA256, algorithms.Hash.SM3_256]:
                        test_cases.append(
                            {
                                "algo_opt": [],
                                "base_policy": [],
                                "allowlist": ["--allowlist", allowlist],
                                "ima_log": il,
                                "rootfs": rfs,
                                "expected_algo": f"{algo}",
                                "expected_source": "allowlist",
                            }
                        )

                    # Cases where the algorithm from the base policy should be kept
                    for al in [[], ["--allowlist", allowlist]]:
                        # Skip the exceptional cases when the algorithm from the
                        # base policy is ambiguous
                        if algo not in [algorithms.Hash.SHA256, algorithms.Hash.SM3_256]:
                            test_cases.append(
                                {
                                    "algo_opt": [],
                                    "base_policy": ["--base-policy", base_policy],
                                    "allowlist": al,
                                    "ima_log": il,
                                    "rootfs": rfs,
                                    "expected_algo": f"{algo}",
                                    "expected_source": "base policy",
                                }
                            )

                        # Cases where the algorithm from the --algo option should be kept
                        for bp in [[], ["--base-policy", base_policy]]:
                            test_cases.append(
                                {
                                    "algo_opt": ["--algo", algo],
                                    "base_policy": bp,
                                    "allowlist": al,
                                    "ima_log": il,
                                    "rootfs": ["--rootfs", rootfs],
                                    "expected_algo": f"{algo}",
                                    "expected_source": "--algo option",
                                }
                            )

        # Create an argument parser
        parent_parser = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparser = main_parser.add_subparsers(title="actions")
        parser = create_runtime_policy.get_arg_parser(subparser, parent_parser)

        for case in test_cases:
            cli_args = ["--verbose"]
            # Prepare argument input
            for k in ["algo_opt", "base_policy", "allowlist", "ima_log", "rootfs"]:
                cli_args.extend(case.get(k, []))

            args = parser.parse_args(cli_args)
            expected_algo = case["expected_algo"]
            expected_source = case["expected_source"]

            with keylimePolicyAssertLogs() as logs:
                _policy = create_runtime_policy.create_runtime_policy(args)
                self.assertIn(
                    f"Using digest algorithm '{expected_algo}' obtained from the {expected_source}",
                    logs.getvalue(),
                    msg=f"ARGS: {' '.join(cli_args)}",
                )

    def test_digest_algorithm_priority_exceptions(self):
        """Test priority algorithms exceptions"""

        test_cases = []

        bp_sha256 = os.path.join(HELPER_DIR, "policy-sha256")
        bp_sm3 = os.path.join(HELPER_DIR, "policy-sm3_256")
        al_sha256 = os.path.join(HELPER_DIR, "allowlist-sha256")
        al_sm3 = os.path.join(HELPER_DIR, "allowlist-sm3_256")

        # Prepare test cases
        for algo in ["sha256", "sm3_256"]:
            ima_log = os.path.join(HELPER_DIR, f"ima-log-{algo}")

            for bp in [[], ["--base-policy", bp_sha256], ["--base-policy", bp_sm3]]:
                for al in [[], ["--allowlist", al_sha256], ["--allowlist", al_sm3]]:
                    test_cases.append(
                        {
                            "base_policy": bp,
                            "allowlist": al,
                            "ima_log": ["--ima-measurement-list", ima_log],
                            "expected_algo": f"{algo}",
                            "expected_source": "IMA measurement list",
                            "expected_mismatch": False,
                        }
                    )

        # Prepare test cases
        for algo in ["sha1", "sha384", "sha512"]:
            ima_log = os.path.join(HELPER_DIR, f"ima-log-{algo}")

            for bp in [["--base-policy", bp_sha256], ["--base-policy", bp_sm3]]:
                for al in [["--allowlist", al_sha256], ["--allowlist", al_sm3]]:
                    test_cases.append(
                        {
                            "base_policy": bp,
                            "allowlist": al,
                            "ima_log": ["--ima-measurement-list", ima_log],
                            "expected_algo": "sha256_or_sm3_256",
                            "expected_source": "",
                            "expected_mismatch": True,
                        }
                    )

        # Create an argument parser
        parent_parser = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparser = main_parser.add_subparsers(title="actions")
        parser = create_runtime_policy.get_arg_parser(subparser, parent_parser)

        for case in test_cases:
            cli_args = ["--verbose"]
            # Prepare argument input
            for k in ["base_policy", "allowlist", "ima_log"]:
                cli_args.extend(case.get(k, []))

            args = parser.parse_args(cli_args)
            expected_algo = case["expected_algo"]
            expected_source = case["expected_source"]

            with keylimePolicyAssertLogs() as logs:
                _policy = create_runtime_policy.create_runtime_policy(args)
                if case["expected_mismatch"]:
                    self.assertIn(
                        f"The digest algorithm in the IMA measurement list does not match the previously set '{expected_algo}' algorithm",
                        logs.getvalue(),
                    )
                else:
                    self.assertIn(
                        f"Using digest algorithm '{expected_algo}' obtained from the {expected_source}",
                        logs.getvalue(),
                    )

    def test_mixed_algorithms_sources(self):
        """Test that mixing digests from different algorithms is not allowed"""
        test_cases = []

        policy_sha1 = os.path.join(HELPER_DIR, "policy-sha1")
        allowlist_sha1 = os.path.join(HELPER_DIR, "allowlist-sha1")
        ima_log_sha1 = os.path.join(HELPER_DIR, "ima-log-sha1")

        rootfs = os.path.join(HELPER_DIR, "rootfs")

        base_test = {
            "algo_opt": ["--algo", "sha1"],
            "base policy": ["--base-policy", policy_sha1],
            "allowlist": ["--allowlist", allowlist_sha1],
            "IMA measurement list": ["--ima-measurement-list", ima_log_sha1],
            "rootfs": ["--rootfs", rootfs],
            "source": "",
        }

        rootfs = os.path.join(HELPER_DIR, "rootfs")
        # Prepare test cases
        for algo in ["sha256", "sha384", "sha512", "sm3_256"]:
            base_policy = ["--base-policy", os.path.join(HELPER_DIR, f"policy-{algo}")]
            allowlist = ["--allowlist", os.path.join(HELPER_DIR, f"allowlist-{algo}")]
            ima_log = [
                "--ima-measurement-list",
                os.path.join(HELPER_DIR, f"ima-log-{algo}"),
            ]

            for source, argument in [
                ("base policy", base_policy),
                ("allowlist", allowlist),
                ("IMA measurement list", ima_log),
            ]:
                case = copy.deepcopy(base_test)
                case[source] = argument
                case["source"] = source
                test_cases.append(case)

        # Create an argument parser
        parent_parser = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparser = main_parser.add_subparsers(title="actions")
        parser = create_runtime_policy.get_arg_parser(subparser, parent_parser)

        for case in test_cases:
            cli_args = []
            # Prepare argument input
            for k in ["algo_opt", "base policy", "allowlist", "IMA measurement list", "rootfs"]:
                cli_args.extend(case.get(k, []))

            args = parser.parse_args(cli_args)

            with keylimePolicyAssertLogs() as logs:
                policy = create_runtime_policy.create_runtime_policy(args)
                self.assertIn(
                    f"The digest algorithm in the {case['source']} does not match the previously set 'sha1' algorithm",
                    logs.getvalue(),
                )
                self.assertEqual(policy, None)

    def test_unknown_algorithm_sources(self):
        """Test that input with digests from unknown algorithms are not allowed"""

        test_cases = []

        policy_sha1 = os.path.join(HELPER_DIR, "policy-sha1")
        allowlist_sha1 = os.path.join(HELPER_DIR, "allowlist-sha1")
        ima_log_sha1 = os.path.join(HELPER_DIR, "ima-log-sha1")

        policy_unknown = ["--base-policy", os.path.join(HELPER_DIR, "policy-unknown")]
        allowlist_unknown = ["--allowlist", os.path.join(HELPER_DIR, "allowlist-unknown")]
        ima_log_unknown = [
            "--ima-measurement-list",
            os.path.join(HELPER_DIR, "ima-log-unknown"),
        ]

        rootfs = os.path.join(HELPER_DIR, "rootfs")

        base_test = {
            "algo_opt": ["--algo", "sha1"],
            "base policy": ["--base-policy", policy_sha1],
            "allowlist": ["--allowlist", allowlist_sha1],
            "IMA measurement list": ["--ima-measurement-list", ima_log_sha1],
            "rootfs": ["--rootfs", rootfs],
            "source": "",
        }

        rootfs = os.path.join(HELPER_DIR, "rootfs")
        # Prepare test cases
        for source, argument in [
            ("base policy", policy_unknown),
            ("allowlist", allowlist_unknown),
            ("IMA measurement list", ima_log_unknown),
        ]:
            case = copy.deepcopy(base_test)
            case[source] = argument
            case["source"] = source
            test_cases.append(case)

        # Create an argument parser
        parent_parser = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparser = main_parser.add_subparsers(title="actions")
        parser = create_runtime_policy.get_arg_parser(subparser, parent_parser)

        for case in test_cases:
            cli_args = ["--verbose"]
            # Prepare argument input
            for k in ["algo_opt", "base policy", "allowlist", "IMA measurement list", "rootfs"]:
                cli_args.extend(case.get(k, []))

            args = parser.parse_args(cli_args)

            with keylimePolicyAssertLogs() as logs:
                policy = create_runtime_policy.create_runtime_policy(args)
                self.assertIn(
                    f"Invalid digest algorithm found in the {case['source']}",
                    logs.getvalue(),
                )
                self.assertEqual(policy, None)
