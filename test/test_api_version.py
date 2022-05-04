"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Red Hat, Inc
"""

import unittest

from keylime import api_version


class APIVersion_Test(unittest.TestCase):
    def test_current_version(self):
        self.assertEqual(api_version.current_version(), "2.1", "Current version is 2.1")

    def test_latest_minor_version(self):
        self.assertEqual(api_version.latest_minor_version("1.0"), "1.0", "Latest version of 1.0 is 1.0")
        self.assertEqual(api_version.latest_minor_version("1"), "1.0", "Latest version of 1 is 1.0")
        self.assertEqual(api_version.latest_minor_version("20"), "0", "No latest version of v20")

    def test_normalize_version(self):
        self.assertEqual(api_version.normalize_version(1), "1.0", "1 (int) normalizes to 1")
        self.assertEqual(api_version.normalize_version("1"), "1.0", "1 (str) normalizes to 1")
        self.assertEqual(api_version.normalize_version(1.0), "1.0", "1.0 (float) normalizes to 1.0")
        self.assertEqual(api_version.normalize_version(1.2), "1.2", "1.2 (float) normalizes to 1.2")
        self.assertEqual(api_version.normalize_version("1.2"), "1.2", "1.2 (string) normalizes to 1.2")
        self.assertEqual(api_version.normalize_version("v3.4"), "3.4", "v3.4 normalizes to 3.4")
        self.assertEqual(api_version.normalize_version("v1a"), "1.0", "v1a normalizes to 1.0")
        self.assertEqual(api_version.normalize_version(0), "0", "0 (int) normalizes to 0")
        self.assertEqual(api_version.normalize_version("v12.03"), "12.3", "v12.03 normalizes to 12.3")
        self.assertEqual(api_version.normalize_version("v13.40"), "13.40", "v13.40 normalizes to 13.40")
        self.assertEqual(api_version.normalize_version("vader"), "vader", "vader normalizes to vader")

    def test_is_supported_version(self):
        self.assertTrue(api_version.is_supported_version("2.0"), "2.0 is a supported version")
        self.assertTrue(api_version.is_supported_version("v2.0"), "v2.0 is a supported version")
        self.assertTrue(api_version.is_supported_version("1.0"), "1.0 is a supported version")
        self.assertTrue(api_version.is_supported_version("v1.0"), "v1.0 is a supported version")
        self.assertFalse(api_version.is_supported_version("0"), "0 is not a supported version")
        self.assertFalse(api_version.is_supported_version("v0"), "v0 is not a supported version")
        self.assertFalse(api_version.is_supported_version("10.0"), "10.0 is not a supported version")
        self.assertFalse(api_version.is_supported_version("vader"), "vader is not a supported version")


if __name__ == "__main__":
    unittest.main()
