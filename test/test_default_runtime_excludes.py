import unittest

from keylime.ima import ima


class TestDefaultRuntimeExcludes(unittest.TestCase):
    def test_memfd_kernel_is_added(self):
        excludes = ima.with_default_excludes([])
        self.assertIn("memfd:kernel", excludes)

    def test_existing_pattern_is_not_duplicated(self):
        excludes = ima.with_default_excludes(["memfd:kernel", "/tmp/.*"])
        self.assertEqual(excludes.count("memfd:kernel"), 1)
        self.assertIn("/tmp/.*", excludes)
