"""
Unit tests for keylime.models.base.types.timestamp module
"""

import unittest
from datetime import datetime, timedelta, timezone

from keylime.models.base.types.timestamp import Timestamp


class TestTimestampNow(unittest.TestCase):
    """Test cases for Timestamp.now() static method"""

    def test_now_returns_datetime(self):
        """Test that now() returns a datetime object"""
        result = Timestamp.now()
        self.assertIsInstance(result, datetime)

    def test_now_returns_utc(self):
        """Test that now() returns UTC timezone"""
        result = Timestamp.now()
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_now_is_recent(self):
        """Test that now() returns current time (within 1 second)"""
        before = datetime.now(tz=timezone.utc)
        result = Timestamp.now()
        after = datetime.now(tz=timezone.utc)

        self.assertGreaterEqual(result, before)
        self.assertLessEqual(result, after)


class TestTimestampLoadDatetime(unittest.TestCase):
    """Test cases for Timestamp._load_datetime() method"""

    def test_load_datetime_utc_unchanged(self):
        """Test that UTC datetime is returned unchanged"""
        ts = Timestamp()
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)

        result = ts._load_datetime(dt)  # pylint: disable=protected-access

        self.assertEqual(result, dt)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_load_datetime_naive_adds_utc(self):
        """Test that naive datetime gets UTC timezone added"""
        ts = Timestamp()
        dt = datetime(2024, 1, 15, 10, 30, 45)  # No timezone

        result = ts._load_datetime(dt)  # pylint: disable=protected-access

        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)
        self.assertEqual(result.hour, 10)
        self.assertEqual(result.minute, 30)
        self.assertEqual(result.second, 45)

    def test_load_datetime_other_timezone_converted(self):
        """Test that non-UTC timezone is converted to UTC"""
        ts = Timestamp()
        # Create datetime in UTC+5
        utc_plus_5 = timezone(timedelta(hours=5))
        dt = datetime(2024, 1, 15, 15, 30, 45, tzinfo=utc_plus_5)

        result = ts._load_datetime(dt)  # pylint: disable=protected-access

        self.assertEqual(result.tzinfo, timezone.utc)
        # 15:30 UTC+5 = 10:30 UTC
        self.assertEqual(result.hour, 10)
        self.assertEqual(result.minute, 30)


class TestTimestampLoadStr(unittest.TestCase):
    """Test cases for Timestamp._load_str() method"""

    def test_load_str_iso8601_with_z(self):
        """Test loading ISO8601 string with 'Z' UTC indicator"""
        ts = Timestamp()
        iso_str = "2024-01-15T10:30:45.123456Z"

        result = ts._load_str(iso_str)  # pylint: disable=protected-access

        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)
        self.assertEqual(result.hour, 10)
        self.assertEqual(result.minute, 30)
        self.assertEqual(result.second, 45)
        self.assertEqual(result.microsecond, 123456)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_load_str_iso8601_with_offset(self):
        """Test loading ISO8601 string with timezone offset"""
        ts = Timestamp()
        iso_str = "2024-01-15T15:30:45+05:00"

        result = ts._load_str(iso_str)  # pylint: disable=protected-access

        # Should be converted to UTC (15:30+05:00 = 10:30 UTC)
        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result.hour, 10)
        self.assertEqual(result.minute, 30)

    def test_load_str_iso8601_without_timezone(self):
        """Test loading ISO8601 string without timezone"""
        ts = Timestamp()
        iso_str = "2024-01-15T10:30:45"

        result = ts._load_str(iso_str)  # pylint: disable=protected-access

        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_load_str_unix_timestamp(self):
        """Test loading Unix timestamp as string"""
        ts = Timestamp()
        unix_str = "1705318245.123456"  # Jan 15, 2024 10:30:45.123456 UTC

        result = ts._load_str(unix_str)  # pylint: disable=protected-access

        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)
        self.assertIsNotNone(result.tzinfo)

    def test_load_str_invalid_format_raises_error(self):
        """Test that invalid string format raises ValueError"""
        ts = Timestamp()
        invalid_str = "not a valid timestamp"

        with self.assertRaises(ValueError) as context:
            ts._load_str(invalid_str)  # pylint: disable=protected-access

        self.assertIn("does not appear to be a valid ISO8601 datetime or Unix timestamp", str(context.exception))


class TestTimestampLoadNumeric(unittest.TestCase):
    """Test cases for Timestamp._load_float() and _load_int() methods"""

    def test_load_float_unix_timestamp(self):
        """Test loading Unix timestamp as float"""
        ts = Timestamp()
        unix_float = 1705318245.123456  # Jan 15, 2024 10:30:45.123456 UTC

        result = ts._load_float(unix_float)  # pylint: disable=protected-access

        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_load_int_unix_timestamp(self):
        """Test loading Unix timestamp as int"""
        ts = Timestamp()
        unix_int = 1705318245  # Jan 15, 2024 10:30:45 UTC

        result = ts._load_int(unix_int)  # pylint: disable=protected-access

        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_load_int_zero(self):
        """Test loading zero Unix timestamp (epoch)"""
        ts = Timestamp()

        result = ts._load_int(0)  # pylint: disable=protected-access

        self.assertEqual(result.year, 1970)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 1)


class TestTimestampCast(unittest.TestCase):
    """Test cases for Timestamp.cast() method"""

    def test_cast_none_returns_none(self):
        """Test that casting None returns None"""
        ts = Timestamp()
        result = ts.cast(None)

        self.assertIsNone(result)

    def test_cast_empty_string_returns_none(self):
        """Test that casting empty string returns None"""
        ts = Timestamp()
        result = ts.cast("")

        self.assertIsNone(result)

    def test_cast_zero_returns_none(self):
        """Test that casting 0 returns None (falsy value behavior)"""
        ts = Timestamp()
        result = ts.cast(0)

        # Note: 0 is treated as falsy, so cast returns None
        self.assertIsNone(result)

    def test_cast_datetime_object(self):
        """Test casting datetime object"""
        ts = Timestamp()
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)

        result = ts.cast(dt)

        self.assertEqual(result, dt)

    def test_cast_str_iso8601(self):
        """Test casting ISO8601 string"""
        ts = Timestamp()
        iso_str = "2024-01-15T10:30:45Z"

        result = ts.cast(iso_str)

        assert result is not None
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_cast_str_unix_timestamp(self):
        """Test casting Unix timestamp string"""
        ts = Timestamp()
        unix_str = "1705318245"

        result = ts.cast(unix_str)

        assert result is not None
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_cast_int(self):
        """Test casting int Unix timestamp"""
        ts = Timestamp()
        unix_int = 1705318245

        result = ts.cast(unix_int)

        assert result is not None
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_cast_float(self):
        """Test casting float Unix timestamp"""
        ts = Timestamp()
        unix_float = 1705318245.123456

        result = ts.cast(unix_float)

        assert result is not None
        self.assertEqual(result.year, 2024)
        self.assertEqual(result.month, 1)
        self.assertEqual(result.day, 15)

    def test_cast_invalid_str_raises_value_error(self):
        """Test that invalid string raises ValueError"""
        ts = Timestamp()
        invalid_str = "not a timestamp"

        with self.assertRaises(ValueError) as context:
            ts.cast(invalid_str)

        self.assertIn("does not appear to be a valid ISO8601 datetime or Unix timestamp", str(context.exception))

    def test_cast_invalid_type_raises_type_error(self):
        """Test that invalid type raises TypeError"""
        ts = Timestamp()
        invalid_value = ["not", "a", "timestamp"]

        with self.assertRaises(TypeError) as context:
            ts.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should be one of 'str', 'int', 'float', or 'datetime'", str(context.exception))

    def test_cast_dict_raises_type_error(self):
        """Test that dict raises TypeError"""
        ts = Timestamp()
        invalid_value = {"not": "a timestamp"}

        with self.assertRaises(TypeError) as context:
            ts.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should be one of 'str', 'int', 'float', or 'datetime'", str(context.exception))


class TestTimestampDumpRender(unittest.TestCase):
    """Test cases for Timestamp._dump() and render() methods"""

    def test_dump_none_returns_none(self):
        """Test that dumping None returns None"""
        ts = Timestamp()
        result = ts._dump(None)  # pylint: disable=protected-access

        self.assertIsNone(result)

    def test_dump_empty_string_returns_none(self):
        """Test that dumping empty string returns None"""
        ts = Timestamp()
        result = ts._dump("")  # pylint: disable=protected-access

        self.assertIsNone(result)

    def test_dump_datetime_returns_iso8601(self):
        """Test that dumping datetime returns ISO8601 string"""
        ts = Timestamp()
        dt = datetime(2024, 1, 15, 10, 30, 45, 123456, tzinfo=timezone.utc)

        result = ts._dump(dt)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("2024-01-15T10:30:45.123456", result)

    def test_dump_int_converts_and_returns_iso8601(self):
        """Test that dumping int converts to datetime and returns ISO8601"""
        ts = Timestamp()
        unix_int = 1705318245

        result = ts._dump(unix_int)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("2024-01-15", result)

    def test_render_none_returns_none(self):
        """Test that rendering None returns None"""
        ts = Timestamp()
        result = ts.render(None)

        self.assertIsNone(result)

    def test_render_empty_string_returns_none(self):
        """Test that rendering empty string returns None"""
        ts = Timestamp()
        result = ts.render("")

        self.assertIsNone(result)

    def test_render_datetime_returns_iso8601(self):
        """Test that rendering datetime returns ISO8601 string with microseconds"""
        ts = Timestamp()
        dt = datetime(2024, 1, 15, 10, 30, 45, 123456, tzinfo=timezone.utc)

        result = ts.render(dt)

        self.assertIsNotNone(result)
        self.assertEqual(result, "2024-01-15T10:30:45.123456+00:00")

    def test_render_iso8601_string_returns_iso8601(self):
        """Test that rendering ISO8601 string returns normalized ISO8601"""
        ts = Timestamp()
        iso_str = "2024-01-15T10:30:45Z"

        result = ts.render(iso_str)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("2024-01-15T10:30:45", result)

    def test_render_unix_int_returns_iso8601(self):
        """Test that rendering Unix timestamp int returns ISO8601"""
        ts = Timestamp()
        unix_int = 1705318245

        result = ts.render(unix_int)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("2024-01-15", result)

    def test_render_unix_float_returns_iso8601(self):
        """Test that rendering Unix timestamp float returns ISO8601"""
        ts = Timestamp()
        unix_float = 1705318245.123456

        result = ts.render(unix_float)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("2024-01-15", result)


class TestTimestampGenerateErrorMsg(unittest.TestCase):
    """Test cases for Timestamp.generate_error_msg() method"""

    def test_generate_error_msg(self):
        """Test that generate_error_msg returns correct message"""
        ts = Timestamp()
        msg = ts.generate_error_msg("any_value")

        self.assertEqual(msg, "must be a valid ISO8601 datetime or Unix timestamp")


class TestTimestampProperties(unittest.TestCase):
    """Test cases for Timestamp properties"""

    def test_native_type_returns_datetime(self):
        """Test that native_type property returns datetime class"""
        ts = Timestamp()

        self.assertEqual(ts.native_type, datetime)


class TestTimestampEdgeCases(unittest.TestCase):
    """Test cases for Timestamp edge cases"""

    def test_cast_iso8601_with_milliseconds(self):
        """Test casting ISO8601 with milliseconds precision"""
        ts = Timestamp()
        iso_str = "2024-01-15T10:30:45.123Z"

        result = ts.cast(iso_str)

        assert result is not None
        self.assertEqual(result.microsecond, 123000)

    def test_cast_iso8601_negative_offset(self):
        """Test casting ISO8601 with negative timezone offset"""
        ts = Timestamp()
        iso_str = "2024-01-15T05:30:45-05:00"  # 5:30 EST = 10:30 UTC

        result = ts.cast(iso_str)

        assert result is not None
        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result.hour, 10)
        self.assertEqual(result.minute, 30)

    def test_cast_naive_datetime_gets_utc(self):
        """Test that naive datetime gets UTC timezone"""
        ts = Timestamp()
        naive_dt = datetime(2024, 1, 15, 10, 30, 45)  # No timezone

        result = ts.cast(naive_dt)

        assert result is not None
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_dump_and_render_are_consistent(self):
        """Test that _dump and render produce same output"""
        ts = Timestamp()
        dt = datetime(2024, 1, 15, 10, 30, 45, 123456, tzinfo=timezone.utc)

        dump_result = ts._dump(dt)  # pylint: disable=protected-access
        render_result = ts.render(dt)

        self.assertEqual(dump_result, render_result)

    def test_roundtrip_datetime_to_string_to_datetime(self):
        """Test roundtrip: datetime -> render -> cast -> datetime"""
        ts = Timestamp()
        original = datetime(2024, 1, 15, 10, 30, 45, 123456, tzinfo=timezone.utc)

        # Convert to string
        iso_str = ts.render(original)

        # Convert back to datetime
        result = ts.cast(iso_str)

        self.assertEqual(result, original)

    def test_roundtrip_int_to_datetime_to_string(self):
        """Test roundtrip: int -> cast -> render"""
        ts = Timestamp()
        unix_int = 1705318245

        # Convert to datetime
        dt = ts.cast(unix_int)

        # Convert to string
        iso_str = ts.render(dt)

        self.assertIsNotNone(iso_str)
        assert iso_str is not None
        self.assertIn("2024-01-15", iso_str)


if __name__ == "__main__":
    unittest.main()
