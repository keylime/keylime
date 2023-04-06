import unittest

from keylime.common.version import str_to_version


class TestVersion(unittest.TestCase):
    def test_str_to_version(self) -> None:
        """Sanity test for the conversion of a version string to a tuple."""
        cases = (
            ("12.34", (12, 34)),
            ("not version", None),
            (' "12.34" ', (12, 34)),
            ('"   12.34"   ', (12, 34)),
        )
        for version, expected in cases:
            with self.subTest(version):
                self.assertEqual(str_to_version(version), expected)
