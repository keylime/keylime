import unittest

from keylime.common.version import str_to_version


class TestVersion(unittest.TestCase):
    def test_str_to_version(self) -> None:
        """Sanity test for the conversion of a version string to a tuple"""

        self.assertEqual(str_to_version("12.34"), (12, 34))
        self.assertEqual(str_to_version("not version"), None)
        self.assertEqual(str_to_version(' "12.34" '), (12, 34))
        self.assertEqual(str_to_version('"   12.34"   '), (12, 34))
