import unittest

from keylime.common import validators
from keylime.ima import ima


class TestDefaultRuntimeExcludes(unittest.TestCase):
    def test_memfd_kernel_is_added(self):
        excludes = ima.with_default_excludes([])
        self.assertIn(r"^memfd:kernel$", excludes)

    def test_existing_pattern_is_not_duplicated(self):
        excludes = ima.with_default_excludes([r"^memfd:kernel$", "/tmp/.*"])
        self.assertEqual(excludes.count(r"^memfd:kernel$"), 1)
        self.assertIn("/tmp/.*", excludes)

    def test_memfd_kernel_matches_exact_ima_name_only(self):
        regex, err = validators.valid_exclude_list(ima.with_default_excludes([]))
        self.assertIsNone(err)
        self.assertIsNotNone(regex)
        self.assertIsNotNone(regex.match("memfd:kernel"))
        self.assertIsNone(regex.match("memfd:kernel-extra"))
        self.assertIsNone(regex.match("not-memfd:kernel"))
