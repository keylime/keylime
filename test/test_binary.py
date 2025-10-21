"""
Unit tests for keylime.models.base.types.binary module
"""

import base64
import unittest

from sqlalchemy.types import LargeBinary, String

from keylime.models.base.types.binary import Binary


class TestBinaryInitialization(unittest.TestCase):
    """Test cases for Binary initialization"""

    def test_init_default_persist_as(self):
        """Test Binary initialization with default persist_as (LargeBinary)"""
        binary = Binary()

        self.assertIsInstance(binary._type_engine, LargeBinary)  # pylint: disable=protected-access

    def test_init_with_largebinary_class(self):
        """Test Binary initialization with LargeBinary class"""
        binary = Binary(persist_as=LargeBinary)

        self.assertIsInstance(binary._type_engine, LargeBinary)  # pylint: disable=protected-access

    def test_init_with_largebinary_instance(self):
        """Test Binary initialization with LargeBinary instance"""
        binary = Binary(persist_as=LargeBinary())

        self.assertIsInstance(binary._type_engine, LargeBinary)  # pylint: disable=protected-access

    def test_init_with_string_class(self):
        """Test Binary initialization with String class"""
        binary = Binary(persist_as=String)

        self.assertIsInstance(binary._type_engine, String)  # pylint: disable=protected-access

    def test_init_with_string_instance(self):
        """Test Binary initialization with String instance"""
        binary = Binary(persist_as=String())

        self.assertIsInstance(binary._type_engine, String)  # pylint: disable=protected-access

    def test_init_with_invalid_type_raises_error(self):
        """Test that Binary initialization with invalid persist_as raises TypeError"""
        with self.assertRaises(TypeError) as context:
            Binary(persist_as=int)  # type: ignore[arg-type]

        self.assertIn("must have a persist_as value of type 'LargeBinary' or 'String'", str(context.exception))


class TestBinaryCast(unittest.TestCase):
    """Test cases for Binary.cast() method"""

    def test_cast_none_returns_none(self):
        """Test that casting None returns None"""
        binary = Binary()
        result = binary.cast(None)

        self.assertIsNone(result)

    def test_cast_empty_string_returns_none(self):
        """Test that casting empty string returns None"""
        binary = Binary()
        result = binary.cast("")

        self.assertIsNone(result)

    def test_cast_bytes_returns_unchanged(self):
        """Test that casting bytes returns them unchanged"""
        binary = Binary()
        data = b"\x03\xff\xaa\x55"

        result = binary.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, bytes)

    def test_cast_base64_string(self):
        """Test casting valid base64 string"""
        binary = Binary()
        data = b"\x03\xff\xaa\x55"
        base64_str = base64.b64encode(data).decode("utf-8")

        result = binary.cast(base64_str)

        self.assertEqual(result, data)

    def test_cast_string_ambiguous_as_base64(self):
        """Test that ambiguous strings (valid as both base64 and hex) are treated as base64"""
        binary = Binary()
        # "03ffaa55" is valid base64, so it's decoded as base64 not hex
        ambiguous_str = "03ffaa55"

        result = binary.cast(ambiguous_str)

        # Should be base64 decoded, not hex decoded
        expected = base64.b64decode(ambiguous_str)
        self.assertEqual(result, expected)

    def test_cast_hex_string_with_prefix(self):
        """Test casting valid hex string with 0x prefix"""
        binary = Binary()
        hex_str = "0x03ffaa55"

        result = binary.cast(hex_str)

        self.assertEqual(result, b"\x03\xff\xaa\x55")

    def test_cast_hex_only_with_0x_prefix(self):
        """Test that hex without 0x may be interpreted as base64 if valid"""
        binary = Binary()
        # Without 0x prefix, strings that are valid base64 are decoded as base64
        hex_str = "DEADBEEF"

        result = binary.cast(hex_str)

        # This is valid base64, so it gets base64 decoded
        expected = base64.b64decode(hex_str)
        self.assertEqual(result, expected)

    def test_cast_hex_string_with_prefix_uppercase(self):
        """Test casting hex string with 0x prefix and uppercase"""
        binary = Binary()
        hex_str = "0x03FFAA55"

        result = binary.cast(hex_str)

        self.assertEqual(result, b"\x03\xff\xaa\x55")

    def test_cast_invalid_string_raises_value_error(self):
        """Test that casting invalid base64/hex string raises ValueError"""
        binary = Binary()
        invalid_str = "not valid base64 or hex!"

        with self.assertRaises(ValueError) as context:
            binary.cast(invalid_str)

        self.assertIn("not valid base64 or hex", str(context.exception))

    def test_cast_invalid_hex_string_raises_value_error(self):
        """Test that casting invalid hex string raises ValueError"""
        binary = Binary()
        invalid_hex = "0xGGHH"  # Invalid hex characters

        with self.assertRaises(ValueError) as context:
            binary.cast(invalid_hex)

        self.assertIn("not valid base64 or hex", str(context.exception))

    def test_cast_odd_length_hex_raises_value_error(self):
        """Test that casting odd-length hex string raises ValueError"""
        binary = Binary()
        odd_hex = "03f"  # Odd number of hex digits

        with self.assertRaises(ValueError) as context:
            binary.cast(odd_hex)

        self.assertIn("not valid base64 or hex", str(context.exception))

    def test_cast_invalid_type_raises_type_error(self):
        """Test that casting invalid type raises TypeError"""
        binary = Binary()
        invalid_value = 12345  # Integer is not valid

        with self.assertRaises(TypeError) as context:
            binary.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should be either 'bytes' or 'str'", str(context.exception))

    def test_cast_list_raises_type_error(self):
        """Test that casting list raises TypeError"""
        binary = Binary()
        invalid_value = [1, 2, 3]

        with self.assertRaises(TypeError) as context:
            binary.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should be either 'bytes' or 'str'", str(context.exception))


class TestBinaryDump(unittest.TestCase):
    """Test cases for Binary._dump() method"""

    def test_dump_none_returns_none(self):
        """Test that dumping None returns None"""
        binary = Binary()
        result = binary._dump(None)  # pylint: disable=protected-access

        self.assertIsNone(result)

    def test_dump_empty_string_returns_none(self):
        """Test that dumping empty string returns None"""
        binary = Binary()
        result = binary._dump("")  # pylint: disable=protected-access

        self.assertIsNone(result)

    def test_dump_bytes_with_largebinary_backend(self):
        """Test dumping bytes with LargeBinary backend returns bytes"""
        binary = Binary(persist_as=LargeBinary)
        data = b"\x03\xff\xaa\x55"

        result = binary._dump(data)  # pylint: disable=protected-access

        self.assertEqual(result, data)
        self.assertIsInstance(result, bytes)

    def test_dump_bytes_with_string_backend(self):
        """Test dumping bytes with String backend returns base64"""
        binary = Binary(persist_as=String)
        data = b"\x03\xff\xaa\x55"

        result = binary._dump(data)  # pylint: disable=protected-access

        expected = base64.b64encode(data).decode("utf-8")
        self.assertEqual(result, expected)
        self.assertIsInstance(result, str)

    def test_dump_base64_string_with_largebinary_backend(self):
        """Test dumping base64 string with LargeBinary backend returns bytes"""
        binary = Binary(persist_as=LargeBinary)
        data = b"\x03\xff\xaa\x55"
        base64_str = base64.b64encode(data).decode("utf-8")

        result = binary._dump(base64_str)  # pylint: disable=protected-access

        self.assertEqual(result, data)
        self.assertIsInstance(result, bytes)

    def test_dump_base64_string_with_string_backend(self):
        """Test dumping base64 string with String backend returns base64"""
        binary = Binary(persist_as=String)
        data = b"\x03\xff\xaa\x55"
        base64_str = base64.b64encode(data).decode("utf-8")

        result = binary._dump(base64_str)  # pylint: disable=protected-access

        self.assertEqual(result, base64_str)
        self.assertIsInstance(result, str)

    def test_dump_hex_string_with_prefix_largebinary_backend(self):
        """Test dumping hex string with 0x prefix and LargeBinary backend returns bytes"""
        binary = Binary(persist_as=LargeBinary)
        hex_str = "0x03ffaa55"  # Use 0x prefix to ensure hex interpretation

        result = binary._dump(hex_str)  # pylint: disable=protected-access

        self.assertEqual(result, b"\x03\xff\xaa\x55")
        self.assertIsInstance(result, bytes)

    def test_dump_hex_string_with_prefix_string_backend(self):
        """Test dumping hex string with 0x prefix and String backend returns base64"""
        binary = Binary(persist_as=String)
        hex_str = "0x03ffaa55"  # Use 0x prefix to ensure hex interpretation
        expected_bytes = b"\x03\xff\xaa\x55"
        expected_base64 = base64.b64encode(expected_bytes).decode("utf-8")

        result = binary._dump(hex_str)  # pylint: disable=protected-access

        self.assertEqual(result, expected_base64)
        self.assertIsInstance(result, str)


class TestBinaryRender(unittest.TestCase):
    """Test cases for Binary.render() method"""

    def test_render_bytes_returns_base64(self):
        """Test that rendering bytes returns base64 string"""
        binary = Binary()
        data = b"\x03\xff\xaa\x55"

        result = binary.render(data)

        expected = base64.b64encode(data).decode("utf-8")
        self.assertEqual(result, expected)
        self.assertIsInstance(result, str)

    def test_render_base64_string_returns_base64(self):
        """Test that rendering base64 string returns base64"""
        binary = Binary()
        data = b"\x03\xff\xaa\x55"
        base64_str = base64.b64encode(data).decode("utf-8")

        result = binary.render(base64_str)

        self.assertEqual(result, base64_str)

    def test_render_hex_string_with_prefix_returns_base64(self):
        """Test that rendering hex string with 0x prefix returns base64"""
        binary = Binary()
        hex_str = "0x03ffaa55"  # Use 0x prefix to ensure hex interpretation
        expected_bytes = b"\x03\xff\xaa\x55"
        expected_base64 = base64.b64encode(expected_bytes).decode("utf-8")

        result = binary.render(hex_str)

        self.assertEqual(result, expected_base64)

    def test_render_with_largebinary_backend_still_returns_base64(self):
        """Test that render always returns base64 regardless of backend"""
        binary = Binary(persist_as=LargeBinary)
        data = b"\x03\xff\xaa\x55"

        result = binary.render(data)

        expected = base64.b64encode(data).decode("utf-8")
        self.assertEqual(result, expected)

    def test_render_with_string_backend_returns_base64(self):
        """Test that render returns base64 with String backend"""
        binary = Binary(persist_as=String)
        data = b"\x03\xff\xaa\x55"

        result = binary.render(data)

        expected = base64.b64encode(data).decode("utf-8")
        self.assertEqual(result, expected)


class TestBinaryProperties(unittest.TestCase):
    """Test cases for Binary properties"""

    def test_native_type_returns_bytes(self):
        """Test that native_type property returns bytes class"""
        binary = Binary()

        self.assertEqual(binary.native_type, bytes)

    def test_generate_error_msg(self):
        """Test that generate_error_msg returns correct message"""
        binary = Binary()

        msg = binary.generate_error_msg(b"any_value")

        self.assertEqual(msg, "must be valid binary")


class TestBinaryEdgeCases(unittest.TestCase):
    """Test cases for Binary edge cases"""

    def test_roundtrip_bytes_to_base64_to_bytes(self):
        """Test roundtrip: bytes -> render -> cast -> bytes"""
        binary = Binary()
        original = b"\x03\xff\xaa\x55\x12\x34\x56\x78"

        # Render to base64
        base64_str = binary.render(original)

        # Cast back to bytes
        result = binary.cast(base64_str)

        self.assertEqual(result, original)

    def test_roundtrip_hex_to_bytes_to_base64(self):
        """Test roundtrip: hex -> cast -> render"""
        binary = Binary()
        hex_str = "0x03ffaa55"

        # Cast hex to bytes
        data = binary.cast(hex_str)

        # Render to base64
        base64_str = binary.render(data)

        # Cast base64 back to bytes
        result = binary.cast(base64_str)

        self.assertEqual(result, b"\x03\xff\xaa\x55")

    def test_empty_bytes_handling(self):
        """Test handling of empty bytes"""
        binary = Binary()
        empty_bytes = b""

        result = binary.cast(empty_bytes)

        # Empty bytes is falsy, so cast returns None
        self.assertIsNone(result)

    def test_single_byte_value(self):
        """Test handling single byte value"""
        binary = Binary()
        single_byte = b"\xff"

        result = binary.cast(single_byte)

        self.assertEqual(result, single_byte)

    def test_large_binary_data(self):
        """Test handling large binary data"""
        binary = Binary()
        large_data = b"\xff" * 1000

        result = binary.cast(large_data)

        self.assertEqual(result, large_data)

    def test_zero_bytes(self):
        """Test handling binary data with zero bytes"""
        binary = Binary()
        zero_data = b"\x00\x00\x00\x00"

        result = binary.cast(zero_data)

        self.assertEqual(result, zero_data)


if __name__ == "__main__":
    unittest.main()
