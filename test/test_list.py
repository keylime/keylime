"""
Unit tests for keylime.models.base.types.list module
"""

import json
import unittest

from sqlalchemy.types import Text

from keylime.models.base.types.list import List


class TestListInitialization(unittest.TestCase):
    """Test cases for List initialization"""

    def test_init_creates_text_backend(self):
        """Test List initialization creates Text backend"""
        list_type = List()

        # List always uses Text backend
        self.assertIsInstance(list_type._type_engine, Text)  # pylint: disable=protected-access


class TestListCast(unittest.TestCase):
    """Test cases for List.cast() method"""

    def test_cast_none_returns_none(self):
        """Test that casting None returns None"""
        list_type = List()
        result = list_type.cast(None)

        self.assertIsNone(result)

    def test_cast_empty_list_returns_empty_list(self):
        """Test that casting empty list returns empty list"""
        list_type = List()
        result = list_type.cast([])

        self.assertEqual(result, [])
        self.assertIsInstance(result, list)

    def test_cast_list_of_strings(self):
        """Test casting list of strings returns unchanged"""
        list_type = List()
        data = ["Alice", "Bob", "Charlie"]

        result = list_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, list)

    def test_cast_list_of_numbers(self):
        """Test casting list of numbers returns unchanged"""
        list_type = List()
        data = [1, 2, 3, 4.5, 6.7]

        result = list_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, list)

    def test_cast_list_of_mixed_types(self):
        """Test casting list of mixed JSON-serializable types"""
        list_type = List()
        data = ["text", 42, 3.14, True, None, {"key": "value"}, [1, 2, 3]]

        result = list_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, list)

    def test_cast_list_of_dicts(self):
        """Test casting list of dictionaries"""
        list_type = List()
        data = [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]

        result = list_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, list)

    def test_cast_nested_lists(self):
        """Test casting nested lists"""
        list_type = List()
        data = [[1, 2], [3, 4], [5, [6, 7]]]

        result = list_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, list)

    def test_cast_list_with_non_json_serializable_raises_error(self):
        """Test that list with non-JSON-serializable content raises TypeError"""
        list_type = List()

        # Objects are not JSON serializable
        class CustomObject:
            pass

        data = [1, 2, CustomObject()]

        with self.assertRaises(TypeError) as context:
            list_type.cast(data)

        self.assertIn("aren't representable as JSON", str(context.exception))

    def test_cast_json_array_string(self):
        """Test casting valid JSON array string"""
        list_type = List()
        json_str = '["Alice", "Bob", "Charlie"]'

        result = list_type.cast(json_str)

        self.assertEqual(result, ["Alice", "Bob", "Charlie"])
        self.assertIsInstance(result, list)

    def test_cast_json_array_string_with_numbers(self):
        """Test casting JSON array string with numbers"""
        list_type = List()
        json_str = "[1, 2, 3, 4.5]"

        result = list_type.cast(json_str)

        self.assertEqual(result, [1, 2, 3, 4.5])
        self.assertIsInstance(result, list)

    def test_cast_json_array_string_with_mixed_types(self):
        """Test casting JSON array string with mixed types"""
        list_type = List()
        json_str = '["text", 42, true, null, {"key": "value"}]'

        result = list_type.cast(json_str)

        self.assertEqual(result, ["text", 42, True, None, {"key": "value"}])
        self.assertIsInstance(result, list)

    def test_cast_json_array_string_empty(self):
        """Test casting empty JSON array string"""
        list_type = List()
        json_str = "[]"

        result = list_type.cast(json_str)

        self.assertEqual(result, [])
        self.assertIsInstance(result, list)

    def test_cast_double_serialized_json(self):
        """Test casting double-serialized JSON (string within string)"""
        list_type = List()
        # First serialization: ["Alice", "Bob"] → '["Alice", "Bob"]'
        # Second serialization: '["Alice", "Bob"]' → '"[\\"Alice\\", \\"Bob\\"]"'
        double_serialized = json.dumps(json.dumps(["Alice", "Bob"]))

        result = list_type.cast(double_serialized)

        self.assertEqual(result, ["Alice", "Bob"])
        self.assertIsInstance(result, list)

    def test_cast_invalid_json_string_raises_value_error(self):
        """Test that invalid JSON string raises ValueError"""
        list_type = List()
        invalid_json = "not valid JSON"

        with self.assertRaises(ValueError) as context:
            list_type.cast(invalid_json)

        self.assertIn("not valid JSON", str(context.exception))

    def test_cast_json_string_not_array_raises_value_error(self):
        """Test that JSON string that's not an array raises ValueError"""
        list_type = List()
        # Valid JSON but not an array
        json_str = '{"key": "value"}'

        with self.assertRaises(ValueError) as context:
            list_type.cast(json_str)

        self.assertIn("not a valid JSON array", str(context.exception))

    def test_cast_json_number_raises_value_error(self):
        """Test that JSON number raises ValueError"""
        list_type = List()
        json_str = "42"

        with self.assertRaises(ValueError) as context:
            list_type.cast(json_str)

        self.assertIn("not a valid JSON array", str(context.exception))

    def test_cast_json_boolean_raises_value_error(self):
        """Test that JSON boolean raises ValueError"""
        list_type = List()
        json_str = "true"

        with self.assertRaises(ValueError) as context:
            list_type.cast(json_str)

        self.assertIn("not a valid JSON array", str(context.exception))

    def test_cast_invalid_type_raises_type_error(self):
        """Test that casting invalid type raises TypeError"""
        list_type = List()
        invalid_value = 12345  # Integer is not valid

        with self.assertRaises(TypeError) as context:
            list_type.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should be either 'str' or 'list'", str(context.exception))

    def test_cast_dict_raises_type_error(self):
        """Test that casting dict raises TypeError"""
        list_type = List()
        invalid_value = {"key": "value"}

        with self.assertRaises(TypeError) as context:
            list_type.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should be either 'str' or 'list'", str(context.exception))

    def test_cast_tuple_raises_type_error(self):
        """Test that casting tuple raises TypeError"""
        list_type = List()
        invalid_value = (1, 2, 3)

        with self.assertRaises(TypeError) as context:
            list_type.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should be either 'str' or 'list'", str(context.exception))


class TestListDump(unittest.TestCase):
    """Test cases for List._dump() method"""

    def test_dump_none_returns_none(self):
        """Test that dumping None returns None"""
        list_type = List()
        result = list_type._dump(None)  # pylint: disable=protected-access

        self.assertIsNone(result)

    def test_dump_empty_list_returns_none(self):
        """Test that dumping empty list returns None"""
        list_type = List()
        result = list_type._dump([])  # pylint: disable=protected-access

        # Empty list is falsy, so returns None
        self.assertIsNone(result)

    def test_dump_list_of_strings(self):
        """Test dumping list of strings returns JSON"""
        list_type = List()
        data = ["Alice", "Bob", "Charlie"]

        result = list_type._dump(data)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(json.loads(result), data)
        self.assertIsInstance(result, str)

    def test_dump_list_of_numbers(self):
        """Test dumping list of numbers returns JSON"""
        list_type = List()
        data = [1, 2, 3, 4.5]

        result = list_type._dump(data)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(json.loads(result), data)
        self.assertIsInstance(result, str)

    def test_dump_list_of_mixed_types(self):
        """Test dumping list of mixed types returns JSON"""
        list_type = List()
        data = ["text", 42, 3.14, True, None]

        result = list_type._dump(data)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(json.loads(result), data)
        self.assertIsInstance(result, str)

    def test_dump_json_string_returns_json(self):
        """Test dumping JSON string returns same JSON representation"""
        list_type = List()
        json_str = '["Alice", "Bob"]'

        result = list_type._dump(json_str)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        # After cast and dump, should be valid JSON
        self.assertEqual(json.loads(result), ["Alice", "Bob"])
        self.assertIsInstance(result, str)

    def test_dump_nested_lists(self):
        """Test dumping nested lists"""
        list_type = List()
        data = [[1, 2], [3, 4], [5, [6, 7]]]

        result = list_type._dump(data)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(json.loads(result), data)
        self.assertIsInstance(result, str)


class TestListRender(unittest.TestCase):
    """Test cases for List.render() method"""

    def test_render_none_returns_none(self):
        """Test that rendering None returns None"""
        list_type = List()
        result = list_type.render(None)

        self.assertIsNone(result)

    def test_render_empty_list_returns_empty_list(self):
        """Test that rendering empty list returns empty list"""
        list_type = List()
        result = list_type.render([])

        self.assertEqual(result, [])
        self.assertIsInstance(result, list)

    def test_render_list_of_strings(self):
        """Test rendering list of strings returns list"""
        list_type = List()
        data = ["Alice", "Bob", "Charlie"]

        result = list_type.render(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, list)

    def test_render_list_of_numbers(self):
        """Test rendering list of numbers returns list"""
        list_type = List()
        data = [1, 2, 3, 4.5]

        result = list_type.render(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, list)

    def test_render_json_string_returns_list(self):
        """Test rendering JSON string returns parsed list"""
        list_type = List()
        json_str = '["Alice", "Bob"]'

        result = list_type.render(json_str)

        self.assertEqual(result, ["Alice", "Bob"])
        self.assertIsInstance(result, list)


class TestListProperties(unittest.TestCase):
    """Test cases for List properties"""

    def test_native_type_returns_list(self):
        """Test that native_type property returns list class"""
        list_type = List()

        self.assertEqual(list_type.native_type, list)

    def test_generate_error_msg(self):
        """Test that generate_error_msg returns correct message"""
        list_type = List()

        msg = list_type.generate_error_msg([1, 2, 3])

        self.assertEqual(msg, "must be a valid JSON array")

    def test_generate_error_msg_with_none(self):
        """Test generate_error_msg with None value"""
        list_type = List()

        msg = list_type.generate_error_msg(None)

        self.assertEqual(msg, "must be a valid JSON array")


class TestListCastAdditional(unittest.TestCase):
    """Additional test cases for List.cast() to improve coverage"""

    def test_cast_empty_list_returns_empty_list(self):
        """Test that casting empty list works correctly"""
        list_type = List()
        result = list_type.cast([])

        self.assertEqual(result, [])
        self.assertIsInstance(result, list)

    def test_cast_json_string_that_is_double_encoded(self):
        """Test that double-encoded JSON strings are handled"""
        list_type = List()
        # First encode: [1, 2, 3] -> "[1, 2, 3]"
        # Second encode: "[1, 2, 3]" -> "\"[1, 2, 3]\""
        double_encoded = json.dumps(json.dumps([1, 2, 3]))

        result = list_type.cast(double_encoded)

        self.assertEqual(result, [1, 2, 3])

    def test_cast_json_object_string_raises_value_error(self):
        """Test that JSON object (not array) raises ValueError"""
        list_type = List()
        json_object = '{"key": "value"}'

        with self.assertRaises(ValueError) as context:
            list_type.cast(json_object)

        self.assertIn("not a valid JSON array", str(context.exception))

    def test_cast_json_primitive_raises_value_error(self):
        """Test that JSON primitives raise ValueError"""
        list_type = List()

        # Test with number
        with self.assertRaises(ValueError):
            list_type.cast("42")

        # Test with boolean
        with self.assertRaises(ValueError):
            list_type.cast("true")

        # Test with null
        with self.assertRaises(ValueError):
            list_type.cast("null")


class TestListDumpAdditional(unittest.TestCase):
    """Additional test cases for List._dump() to improve coverage"""

    def test_dump_empty_list_returns_none(self):
        """Test that dumping empty list returns None"""
        list_type = List()
        result = list_type._dump([])  # pylint: disable=protected-access

        # Empty list is falsy, so returns None
        self.assertIsNone(result)

    def test_dump_list_with_complex_types(self):
        """Test dumping list with complex nested types"""
        list_type = List()
        complex_list = [
            {"name": "Alice", "scores": [90, 85, 88]},
            {"name": "Bob", "scores": [75, 80, 82]},
            [1, 2, [3, 4]],
        ]

        result = list_type._dump(complex_list)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None  # For type checker
        # Verify it's valid JSON
        parsed = json.loads(result)
        self.assertEqual(parsed, complex_list)

    def test_dump_json_string_input(self):
        """Test that _dump can handle JSON string input"""
        list_type = List()
        json_str = "[1, 2, 3]"

        result = list_type._dump(json_str)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        # Should parse the string and re-dump it
        self.assertEqual(json.loads(result), [1, 2, 3])


class TestListEdgeCases(unittest.TestCase):
    """Test cases for List edge cases"""

    def test_roundtrip_list_to_json_to_list(self):
        """Test roundtrip: list -> render -> cast -> list"""
        list_type = List()
        original = ["Alice", "Bob", "Charlie", 42, 3.14]

        # Render to JSON
        json_str = list_type.render(original)

        # Cast back to list
        result = list_type.cast(json_str)

        self.assertEqual(result, original)

    def test_roundtrip_json_to_list_to_json(self):
        """Test roundtrip: JSON -> cast -> render"""
        list_type = List()
        json_str = '["Alice", "Bob", 42]'

        # Cast to list
        data = list_type.cast(json_str)

        # Render returns list (not JSON string)
        result = list_type.render(data)

        assert result is not None
        self.assertEqual(result, ["Alice", "Bob", 42])
        self.assertEqual(result, data)

    def test_cast_list_with_unicode(self):
        """Test casting list with unicode characters"""
        list_type = List()
        data = ["Hello", "世界", "🌍", "Здравствуй"]

        result = list_type.cast(data)

        self.assertEqual(result, data)

    def test_cast_json_with_unicode(self):
        """Test casting JSON string with unicode characters"""
        list_type = List()
        json_str = '["Hello", "世界", "🌍"]'

        result = list_type.cast(json_str)

        self.assertEqual(result, ["Hello", "世界", "🌍"])

    def test_cast_large_list(self):
        """Test casting large list"""
        list_type = List()
        large_list = list(range(1000))

        result = list_type.cast(large_list)

        self.assertEqual(result, large_list)

    def test_dump_preserves_json_structure(self):
        """Test that dump preserves complex JSON structure"""
        list_type = List()
        complex_data = [
            {"name": "Alice", "scores": [90, 85, 88]},
            {"name": "Bob", "scores": [75, 80, 82]},
        ]

        result = list_type._dump(complex_data)  # pylint: disable=protected-access

        assert result is not None
        self.assertEqual(json.loads(result), complex_data)


if __name__ == "__main__":
    unittest.main()
