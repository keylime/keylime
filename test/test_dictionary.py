"""
Unit tests for keylime.models.base.types.dictionary module
"""

import json
import unittest

from sqlalchemy.types import Text

from keylime.models.base.types.dictionary import Dictionary


class TestDictionaryInitialization(unittest.TestCase):
    """Test cases for Dictionary initialization"""

    def test_init_creates_text_backend(self):
        """Test Dictionary initialization creates Text backend"""
        dict_type = Dictionary()

        # Dictionary always uses Text backend
        self.assertIsInstance(dict_type._type_engine, Text)  # pylint: disable=protected-access


class TestDictionaryCast(unittest.TestCase):
    """Test cases for Dictionary.cast() method"""

    def test_cast_none_returns_none(self):
        """Test that casting None returns None"""
        dict_type = Dictionary()
        result = dict_type.cast(None)

        self.assertIsNone(result)

    def test_cast_empty_dict_returns_empty_dict(self):
        """Test that casting empty dict returns empty dict"""
        dict_type = Dictionary()
        result = dict_type.cast({})

        self.assertEqual(result, {})
        self.assertIsInstance(result, dict)

    def test_cast_dict_of_strings(self):
        """Test casting dict of strings returns unchanged"""
        dict_type = Dictionary()
        data = {"name": "Alice", "city": "Boston", "country": "USA"}

        result = dict_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, dict)

    def test_cast_dict_of_numbers(self):
        """Test casting dict of numbers returns unchanged"""
        dict_type = Dictionary()
        data = {"age": 30, "score": 95.5, "count": 42}

        result = dict_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, dict)

    def test_cast_dict_of_mixed_types(self):
        """Test casting dict of mixed JSON-serializable types"""
        dict_type = Dictionary()
        data = {
            "name": "Alice",
            "age": 30,
            "score": 3.14,
            "active": True,
            "notes": None,
            "tags": ["tag1", "tag2"],
            "metadata": {"key": "value"},
        }

        result = dict_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, dict)

    def test_cast_nested_dicts(self):
        """Test casting nested dicts"""
        dict_type = Dictionary()
        data = {"user": {"name": "Alice", "address": {"city": "Boston", "zip": "02101"}}}

        result = dict_type.cast(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, dict)

    def test_cast_dict_with_non_json_serializable_raises_error(self):
        """Test that dict with non-JSON-serializable content raises TypeError"""
        dict_type = Dictionary()

        # Objects are not JSON serializable
        class CustomObject:
            pass

        data = {"key": "value", "obj": CustomObject()}

        with self.assertRaises(TypeError) as context:
            dict_type.cast(data)

        self.assertIn("aren't representable as JSON", str(context.exception))

    def test_cast_json_object_string(self):
        """Test casting valid JSON object string"""
        dict_type = Dictionary()
        json_str = '{"name": "Alice", "age": 30}'

        result = dict_type.cast(json_str)

        self.assertEqual(result, {"name": "Alice", "age": 30})
        self.assertIsInstance(result, dict)

    def test_cast_json_object_string_with_nested_objects(self):
        """Test casting JSON object string with nested objects"""
        dict_type = Dictionary()
        json_str = '{"user": {"name": "Alice", "age": 30}}'

        result = dict_type.cast(json_str)

        self.assertEqual(result, {"user": {"name": "Alice", "age": 30}})
        self.assertIsInstance(result, dict)

    def test_cast_json_object_string_empty(self):
        """Test casting empty JSON object string"""
        dict_type = Dictionary()
        json_str = "{}"

        result = dict_type.cast(json_str)

        self.assertEqual(result, {})
        self.assertIsInstance(result, dict)

    def test_cast_double_serialized_json(self):
        """Test casting double-serialized JSON (string within string)"""
        dict_type = Dictionary()
        # First serialization: {"key": "value"} → '{"key": "value"}'
        # Second serialization: '{"key": "value"}' → '"{\\\"key\\\": \\\"value\\\"}"'
        double_serialized = json.dumps(json.dumps({"key": "value"}))

        result = dict_type.cast(double_serialized)

        self.assertEqual(result, {"key": "value"})
        self.assertIsInstance(result, dict)

    def test_cast_invalid_json_string_raises_value_error(self):
        """Test that invalid JSON string raises ValueError"""
        dict_type = Dictionary()
        invalid_json = "not valid JSON"

        with self.assertRaises(ValueError) as context:
            dict_type.cast(invalid_json)

        self.assertIn("not valid JSON", str(context.exception))

    def test_cast_json_string_not_object_raises_value_error(self):
        """Test that JSON string that's not an object raises ValueError"""
        dict_type = Dictionary()
        # Valid JSON but not an object
        json_str = '["array", "not", "object"]'

        with self.assertRaises(ValueError) as context:
            dict_type.cast(json_str)

        self.assertIn("not a valid JSON object", str(context.exception))

    def test_cast_json_number_raises_value_error(self):
        """Test that JSON number raises ValueError"""
        dict_type = Dictionary()
        json_str = "42"

        with self.assertRaises(ValueError) as context:
            dict_type.cast(json_str)

        self.assertIn("not a valid JSON object", str(context.exception))

    def test_cast_json_boolean_raises_value_error(self):
        """Test that JSON boolean raises ValueError"""
        dict_type = Dictionary()
        json_str = "true"

        with self.assertRaises(ValueError) as context:
            dict_type.cast(json_str)

        self.assertIn("not a valid JSON object", str(context.exception))

    def test_cast_invalid_type_raises_type_error(self):
        """Test that casting invalid type raises TypeError"""
        dict_type = Dictionary()
        invalid_value = 12345  # Integer is not valid

        with self.assertRaises(TypeError) as context:
            dict_type.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should either 'str' or 'dict'", str(context.exception))

    def test_cast_list_raises_type_error(self):
        """Test that casting list raises TypeError"""
        dict_type = Dictionary()
        invalid_value = ["not", "a", "dict"]

        with self.assertRaises(TypeError) as context:
            dict_type.cast(invalid_value)  # type: ignore[arg-type]

        self.assertIn("should either 'str' or 'dict'", str(context.exception))


class TestDictionaryDump(unittest.TestCase):
    """Test cases for Dictionary._dump() method"""

    def test_dump_none_returns_none(self):
        """Test that dumping None returns None"""
        dict_type = Dictionary()
        result = dict_type._dump(None)  # pylint: disable=protected-access

        self.assertIsNone(result)

    def test_dump_empty_dict_returns_none(self):
        """Test that dumping empty dict returns None"""
        dict_type = Dictionary()
        result = dict_type._dump({})  # pylint: disable=protected-access

        # Empty dict is falsy, so returns None
        self.assertIsNone(result)

    def test_dump_dict_of_strings(self):
        """Test dumping dict of strings returns JSON"""
        dict_type = Dictionary()
        data = {"name": "Alice", "city": "Boston"}

        result = dict_type._dump(data)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(json.loads(result), data)
        self.assertIsInstance(result, str)

    def test_dump_dict_of_mixed_types(self):
        """Test dumping dict of mixed types returns JSON"""
        dict_type = Dictionary()
        data = {"name": "Alice", "age": 30, "score": 95.5, "active": True}

        result = dict_type._dump(data)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(json.loads(result), data)
        self.assertIsInstance(result, str)

    def test_dump_json_string_returns_json(self):
        """Test dumping JSON string returns same JSON representation"""
        dict_type = Dictionary()
        json_str = '{"name": "Alice"}'

        result = dict_type._dump(json_str)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        # After cast and dump, should be valid JSON
        self.assertEqual(json.loads(result), {"name": "Alice"})
        self.assertIsInstance(result, str)

    def test_dump_nested_dicts(self):
        """Test dumping nested dicts"""
        dict_type = Dictionary()
        data = {"user": {"name": "Alice", "address": {"city": "Boston"}}}

        result = dict_type._dump(data)  # pylint: disable=protected-access

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(json.loads(result), data)
        self.assertIsInstance(result, str)


class TestDictionaryRender(unittest.TestCase):
    """Test cases for Dictionary.render() method"""

    def test_render_none_returns_none(self):
        """Test that rendering None returns None"""
        dict_type = Dictionary()
        result = dict_type.render(None)

        self.assertIsNone(result)

    def test_render_empty_dict_returns_empty_dict(self):
        """Test that rendering empty dict returns empty dict"""
        dict_type = Dictionary()
        result = dict_type.render({})

        self.assertEqual(result, {})
        self.assertIsInstance(result, dict)

    def test_render_dict_returns_dict(self):
        """Test rendering dict returns dict"""
        dict_type = Dictionary()
        data = {"name": "Alice", "age": 30}

        result = dict_type.render(data)

        self.assertEqual(result, data)
        self.assertIsInstance(result, dict)

    def test_render_json_string_returns_dict(self):
        """Test rendering JSON string returns parsed dict"""
        dict_type = Dictionary()
        json_str = '{"name": "Alice"}'

        result = dict_type.render(json_str)

        self.assertEqual(result, {"name": "Alice"})
        self.assertIsInstance(result, dict)


class TestDictionaryProperties(unittest.TestCase):
    """Test cases for Dictionary properties"""

    def test_native_type_returns_dict(self):
        """Test that native_type property returns dict class"""
        dict_type = Dictionary()

        self.assertEqual(dict_type.native_type, dict)

    def test_generate_error_msg(self):
        """Test that generate_error_msg returns correct message"""
        dict_type = Dictionary()

        msg = dict_type.generate_error_msg({"key": "value"})

        self.assertEqual(msg, "must be a valid JSON object")

    def test_generate_error_msg_with_none(self):
        """Test generate_error_msg with None value"""
        dict_type = Dictionary()

        msg = dict_type.generate_error_msg(None)

        self.assertEqual(msg, "must be a valid JSON object")


class TestDictionaryEdgeCases(unittest.TestCase):
    """Test cases for Dictionary edge cases"""

    def test_roundtrip_dict_to_json_to_dict(self):
        """Test roundtrip: dict -> render -> cast -> dict"""
        dict_type = Dictionary()
        original = {"name": "Alice", "age": 30, "score": 95.5}

        # Render to dict (no serialization in render, just cast)
        rendered = dict_type.render(original)

        # Cast back to dict
        result = dict_type.cast(rendered)

        self.assertEqual(result, original)

    def test_roundtrip_json_to_dict_to_json(self):
        """Test roundtrip: JSON -> cast -> render"""
        dict_type = Dictionary()
        json_str = '{"name": "Alice", "age": 30}'

        # Cast to dict
        data = dict_type.cast(json_str)

        # Render returns dict (not JSON string)
        result = dict_type.render(data)

        assert result is not None
        self.assertEqual(result, {"name": "Alice", "age": 30})
        self.assertEqual(result, data)

    def test_cast_dict_with_unicode(self):
        """Test casting dict with unicode characters"""
        dict_type = Dictionary()
        data = {"greeting": "Hello", "chinese": "世界", "emoji": "🌍", "russian": "Здравствуй"}

        result = dict_type.cast(data)

        self.assertEqual(result, data)

    def test_cast_json_with_unicode(self):
        """Test casting JSON string with unicode characters"""
        dict_type = Dictionary()
        json_str = '{"greeting": "Hello", "chinese": "世界", "emoji": "🌍"}'

        result = dict_type.cast(json_str)

        self.assertEqual(result, {"greeting": "Hello", "chinese": "世界", "emoji": "🌍"})

    def test_dump_preserves_json_structure(self):
        """Test that dump preserves complex JSON structure"""
        dict_type = Dictionary()
        complex_data = {"users": [{"name": "Alice", "scores": [90, 85, 88]}, {"name": "Bob", "scores": [75, 80, 82]}]}

        result = dict_type._dump(complex_data)  # pylint: disable=protected-access

        assert result is not None
        self.assertEqual(json.loads(result), complex_data)


if __name__ == "__main__":
    unittest.main()
