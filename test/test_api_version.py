import unittest

from keylime import api_version


class APIVersion_Test(unittest.TestCase):
    """Test to check API version."""

    def test_current_version(self):
        """Test current_version."""
        self.assertEqual(api_version.current_version(), "2.5", "Current version is 2.5")

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

    def test_negotiate_version_with_string(self):
        """Test negotiate_version with a single version string."""
        # Single version that is supported
        result = api_version.negotiate_version("2.0")
        self.assertEqual(result, "2.0")

        # Single version that is not supported
        result = api_version.negotiate_version("99.0")
        self.assertIsNone(result)

    def test_negotiate_version_with_list(self):
        """Test negotiate_version with a list of versions."""
        # List with multiple supported versions - should return highest
        result = api_version.negotiate_version(["1.0", "2.0", "2.1"])
        self.assertEqual(result, "2.1")

        # List with mixed supported/unsupported - should return highest supported
        result = api_version.negotiate_version(["1.0", "2.0", "99.0"])
        self.assertEqual(result, "2.0")

        # List with no supported versions
        result = api_version.negotiate_version(["98.0", "99.0"])
        self.assertIsNone(result)

    def test_negotiate_version_returns_highest(self):
        """Test that negotiate_version returns the highest common version."""
        # All versions supported by both
        result = api_version.negotiate_version(["1.0", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5"])
        self.assertEqual(result, "2.5")

        # Only lower versions in common
        result = api_version.negotiate_version(["1.0", "2.0"])
        self.assertEqual(result, "2.0")

    def test_negotiate_version_with_custom_local_versions(self):
        """Test negotiate_version with custom local_versions."""
        # Restrict local versions to exclude 3.0 (simulating pull mode)
        local_versions = ["1.0", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5"]
        result = api_version.negotiate_version(["2.5", "3.0"], local_versions)
        self.assertEqual(result, "2.5")

        # Remote only has 3.0, local doesn't support it
        result = api_version.negotiate_version(["3.0"], local_versions)
        self.assertIsNone(result)

        # Both support 3.0 when included in local
        local_versions_with_3 = ["1.0", "2.0", "2.5", "3.0"]
        result = api_version.negotiate_version(["2.5", "3.0"], local_versions_with_3)
        self.assertEqual(result, "3.0")

    def test_negotiate_version_raise_on_error(self):
        """Test negotiate_version with raise_on_error=True."""
        # No compatible version should raise ValueError
        with self.assertRaises(ValueError) as context:
            api_version.negotiate_version(["99.0"], raise_on_error=True)
        self.assertIn("No compatible API version", str(context.exception))

        # Compatible version should not raise
        result = api_version.negotiate_version(["2.0"], raise_on_error=True)
        self.assertEqual(result, "2.0")

    def test_negotiate_version_empty_list(self):
        """Test negotiate_version with empty list."""
        result = api_version.negotiate_version([])
        self.assertIsNone(result)

        # With raise_on_error
        with self.assertRaises(ValueError):
            api_version.negotiate_version([], raise_on_error=True)

    def test_negotiate_version_proper_version_comparison(self):
        """Test that version comparison is numeric, not string-based (2.10 > 2.2)."""
        # String comparison would incorrectly say "2.2" > "2.10" because "2" > "1"
        # Proper version comparison should correctly identify 2.10 > 2.2
        local_versions = ["2.2", "2.10"]
        remote_versions = ["2.2", "2.10"]
        result = api_version.negotiate_version(remote_versions, local_versions)
        self.assertEqual(result, "2.10", "2.10 should be greater than 2.2")

        # Test with more versions to ensure proper ordering
        local_versions = ["1.0", "2.1", "2.2", "2.9", "2.10", "2.11"]
        remote_versions = ["2.2", "2.9", "2.10"]
        result = api_version.negotiate_version(remote_versions, local_versions)
        self.assertEqual(result, "2.10", "2.10 should be the highest common version")


if __name__ == "__main__":
    unittest.main()
