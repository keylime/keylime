import unittest

from keylime.common import validators


class TestValidRegex(unittest.TestCase):
    """Tests for valid_regex."""

    def test_none(self):
        """Check that None is a valid regex."""
        self.assertEqual(validators.valid_regex(None), (True, None, None))

    def test_valid(self):
        """Check a well formed regex."""
        value = validators.valid_regex(r"a.*")
        self.assertTrue(value[0])
        self.assertEqual(value[1].pattern, r"a.*")
        self.assertEqual(value[2], None)

    def test_invalid(self):
        """Check a not valid regex."""
        value = validators.valid_regex(r"a[")
        self.assertEqual(
            value, (False, None, "Invalid regex: unterminated character set.")
        )


class TestValidExcludeList(unittest.TestCase):
    """Tests for valid_exclude_list."""

    def test_none(self):
        """Check that the empty list is valid."""
        self.assertEqual(validators.valid_exclude_list(None), (True, None, None))

    def test_single(self):
        """Check a single exclude list element."""
        value = validators.valid_exclude_list([r"a.*"])
        self.assertTrue(value[0])
        self.assertEqual(value[1].pattern, r"(a.*)")
        self.assertEqual(value[2], None)

    def test_multi(self):
        """Check a multiple elements exclude list."""
        value = validators.valid_exclude_list([r"a.*", r"b.*"])
        self.assertTrue(value[0])
        self.assertEqual(value[1].pattern, r"(a.*)|(b.*)")
        self.assertEqual(value[2], None)

    def test_invalid(self):
        """Check an invalid exclude list."""
        value = validators.valid_exclude_list([r"a["])
        self.assertEqual(
            value, (False, None, "Invalid regex: unterminated character set.")
        )


class TestValidHex(unittest.TestCase):
    """Tests for valid_hex."""

    def test_none(self):
        """Check that None is not valid."""
        self.assertFalse(validators.valid_hex(None))

    def test_empty(self):
        """Check that the empty string is not valid."""
        self.assertFalse(validators.valid_hex(""))

    def test_valid_lower(self):
        """Check a valid lower case hexadecimal number."""
        self.assertTrue(validators.valid_hex("123abc"))

    def test_valid_upper(self):
        """Check a valid upper case hexadecimal number."""
        self.assertTrue(validators.valid_hex("123ABC"))

    def test_invalid(self):
        """Check and invalid hexadecimal number."""
        self.assertFalse(validators.valid_hex("123xyz"))


if __name__ == "__main__":
    unittest.main()
