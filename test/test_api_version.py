import unittest

from keylime import api_version


class APIVersion_Test(unittest.TestCase):
    """Test to check API version."""

    def test_current_version(self):
        """Test current_version."""
        self.assertEqual(api_version.current_version(), "2.3", "Current version is 2.3")

    def test_latest_minor_version(self):
        """Test laster_minor_version."""
        cases = (
            ("Latest version of 1.0 is 1.0", "1.0", "1.0"),
            ("Latest version of 1 is 1.0", "1", "1.0"),
            ("No latest version of v20", "20", "0"),
        )
        for description, version, expected in cases:
            with self.subTest(description):
                self.assertEqual(api_version.latest_minor_version(version), expected, description)

    def test_normalize_version(self):
        """Test normalize_version."""
        cases = (
            ("1 (int) normalizes to 1", 1, "1.0"),
            ("1 (str) normalizes to 1", "1", "1.0"),
            ("1.0 (float) normalizes to 1.0", 1.0, "1.0"),
            ("1.2 (float) normalizes to 1.2", 1.2, "1.2"),
            ("1.2 (string) normalizes to 1.2", "1.2", "1.2"),
            ("v3.4 normalizes to 3.4", "v3.4", "3.4"),
            ("v1a normalizes to 1.0", "v1a", "1.0"),
            ("0 (int) normalizes to 0", 0, "0"),
            ("v12.03 normalizes to 12.3", "v12.03", "12.3"),
            ("v13.40 normalizes to 13.40", "v13.40", "13.40"),
            ("vader normalizes to vader", "vader", "vader"),
        )
        for description, version, expected in cases:
            with self.subTest(description):
                self.assertEqual(api_version.normalize_version(version), expected, description)

    def test_is_supported_version(self):
        """Test is_supported_version."""
        cases = (
            ("2.0 is a supported version", "2.0", True),
            ("v2.0 is a supported version", "v2.0", True),
            ("1.0 is a supported version", "1.0", True),
            ("v1.0 is a supported version", "v1.0", True),
            ("0 is not a supported version", "0", False),
            ("v0 is not a supported version", "v0", False),
            ("10.0 is not a supported version", "10.0", False),
            ("vader is not a supported version", "vader", False),
        )
        for description, version, supported in cases:
            with self.subTest(description):
                self.assertEqual(api_version.is_supported_version(version), supported, description)


if __name__ == "__main__":
    unittest.main()
