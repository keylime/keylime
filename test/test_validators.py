import unittest

from keylime.common import validators


class TestValidRegex(unittest.TestCase):
    """Tests for valid_regex."""

    def test_none(self):
        """Check that None is a valid regex."""
        self.assertEqual(validators.valid_regex(None), (None, None))

    def test_valid(self):
        """Check a well formed regex."""
        value = validators.valid_regex(r"a.*")
        assert value[0] is not None
        self.assertEqual(value[0].pattern, r"a.*")
        self.assertEqual(value[1], None)

    def test_invalid(self):
        """Check a not valid regex."""
        value = validators.valid_regex(r"a[")
        self.assertEqual(value, (None, "Invalid regex: unterminated character set."))


class TestValidExcludeList(unittest.TestCase):
    """Tests for valid_exclude_list."""

    def test_none(self):
        """Check that the empty list is valid."""
        self.assertEqual(validators.valid_exclude_list(None), (None, None))

    def test_single(self):
        """Check a single exclude list element."""
        value = validators.valid_exclude_list([r"a.*"])
        assert value[0] is not None
        self.assertEqual(value[0].pattern, r"(a.*)")
        self.assertEqual(value[1], None)

    def test_multi(self):
        """Check a multiple elements exclude list."""
        value = validators.valid_exclude_list([r"a.*", r"b.*"])
        assert value[0] is not None
        self.assertEqual(value[0].pattern, r"(a.*)|(b.*)")
        self.assertEqual(value[1], None)

    def test_invalid(self):
        """Check an invalid exclude list."""
        value = validators.valid_exclude_list([r"a["])
        self.assertEqual(value, (None, "Invalid regex: unterminated character set."))


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


class TestValidUUID(unittest.TestCase):
    """Tests for valid_uuid."""

    def test_none(self):
        """Check that None is not valid."""
        self.assertFalse(validators.valid_uuid(None))

    def test_empty(self):
        """Check that the empty string is not valid."""
        self.assertFalse(validators.valid_uuid(""))

    def test_valid(self):
        """Check a valid UUID that mix upper and lower case."""
        self.assertTrue(validators.valid_uuid("74a93e15-da24-4ff1-ABC0-55beed02a16a"))

    def test_invalid(self):
        """Check an invalid UUID that mix upper and lower case."""
        self.assertFalse(validators.valid_uuid("some text"))


class TestValidAgentID(unittest.TestCase):
    """Tests for valid_agent_id."""

    def test_none(self):
        """Check that None is not valid."""
        self.assertFalse(validators.valid_agent_id(None))

    def test_empty(self):
        """Check that the empty string is not valid."""
        self.assertFalse(validators.valid_agent_id(""))

    def test_valid_uuid(self):
        """Check a valid UUID that mix upper and lower case."""
        self.assertTrue(validators.valid_agent_id("74a93e15-da24-4ff1-ABC0-55beed02a16a"))

    def test_valid_hostname(self):
        """Check a valid hostname that mix upper and lower case."""
        self.assertTrue(validators.valid_agent_id("my-Hostname.example.com"))

    def test_invalid(self):
        """Check an invalid user ID with non valid characters."""
        self.assertFalse(validators.valid_agent_id("rm -fr *"))


if __name__ == "__main__":
    unittest.main()
