"""
Unit tests for keylime.models.base.types.one_of module
"""

# pylint: disable=protected-access
# Testing protected methods of OneOf class

import unittest
from unittest.mock import MagicMock

from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.types import Float, Integer, String

from keylime.models.base.errors import FieldDefinitionInvalid
from keylime.models.base.type import ModelType
from keylime.models.base.types.one_of import OneOf


class MockModelType(ModelType):
    """Mock ModelType for testing"""

    def __init__(self):
        super().__init__(String())

    def cast(self, value):
        if value == "mock_castable":
            return "mock_casted"
        raise ValueError("Not castable")

    def render(self, value):
        if value == "mock_renderable":
            return "mock_rendered"
        raise ValueError("Not renderable")

    def db_dump(self, value, dialect):  # pylint: disable=unused-argument
        if value == "mock_dumpable":
            return "mock_dumped"
        raise ValueError("Not dumpable")

    def db_load(self, value, dialect):  # pylint: disable=unused-argument
        if value == "mock_loadable":
            return "mock_loaded"
        raise ValueError("Not loadable")

    def da_dump(self, value):
        if value == "mock_da_dumpable":
            return "mock_da_dumped"
        raise ValueError("Not DA dumpable")

    def da_load(self, value):
        if value == "mock_da_loadable":
            return "mock_da_loaded"
        raise ValueError("Not DA loadable")


class TestOneOfInitialization(unittest.TestCase):
    """Test cases for OneOf initialization"""

    def test_init_with_string_literals(self):
        """Test OneOf initialization with string literals"""
        one_of = OneOf("pending", "successful", "failed")

        self.assertEqual(len(one_of.permitted), 3)
        self.assertIn("pending", one_of.permitted)
        self.assertIn("successful", one_of.permitted)
        self.assertIn("failed", one_of.permitted)

    def test_init_with_int_literals(self):
        """Test OneOf initialization with integer literals"""
        one_of = OneOf(1, 2, 3)

        self.assertEqual(len(one_of.permitted), 3)
        self.assertIn(1, one_of.permitted)
        self.assertIn(2, one_of.permitted)
        self.assertIn(3, one_of.permitted)

    def test_init_with_float_literals(self):
        """Test OneOf initialization with float literals"""
        one_of = OneOf(1.0, 2.5, 3.7)

        self.assertEqual(len(one_of.permitted), 3)
        self.assertIn(1.0, one_of.permitted)
        self.assertIn(2.5, one_of.permitted)
        self.assertIn(3.7, one_of.permitted)

    def test_init_with_mixed_literals(self):
        """Test OneOf initialization with mixed literal types"""
        one_of = OneOf("text", 42, 3.14)

        self.assertEqual(len(one_of.permitted), 3)
        self.assertIn("text", one_of.permitted)
        self.assertIn(42, one_of.permitted)
        self.assertIn(3.14, one_of.permitted)

    def test_init_with_model_type_instance(self):
        """Test OneOf initialization with ModelType instance"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        self.assertEqual(len(one_of.permitted), 2)
        self.assertIn(mock_type, one_of.permitted)
        self.assertIn("disabled", one_of.permitted)

    def test_init_with_model_type_class(self):
        """Test OneOf initialization with ModelType class"""
        one_of = OneOf(MockModelType, "disabled")

        self.assertEqual(len(one_of.permitted), 2)
        self.assertIsInstance(one_of.permitted[0], MockModelType)
        self.assertIn("disabled", one_of.permitted)

    def test_init_with_type_engine_instance(self):
        """Test OneOf initialization with TypeEngine instance"""
        one_of = OneOf(String(), "text")

        self.assertEqual(len(one_of.permitted), 2)
        # First item should be wrapped in ModelType
        self.assertIsInstance(one_of.permitted[0], ModelType)
        self.assertIn("text", one_of.permitted)

    def test_init_with_type_engine_class(self):
        """Test OneOf initialization with TypeEngine class"""
        one_of = OneOf(String, "text")

        self.assertEqual(len(one_of.permitted), 2)
        self.assertIsInstance(one_of.permitted[0], ModelType)
        self.assertIn("text", one_of.permitted)

    def test_init_with_invalid_type_raises_error(self):
        """Test that OneOf initialization with invalid type raises FieldDefinitionInvalid"""
        with self.assertRaises(FieldDefinitionInvalid) as context:
            OneOf("valid", None, "also_valid")  # type: ignore[arg-type]  # None is not allowed

        self.assertIn("invalid 'OneOf' construct", str(context.exception))

    def test_init_with_list_raises_error(self):
        """Test that OneOf initialization with list raises FieldDefinitionInvalid"""
        with self.assertRaises(FieldDefinitionInvalid) as context:
            OneOf("valid", ["not", "valid"])  # type: ignore[arg-type]

        self.assertIn("invalid 'OneOf' construct", str(context.exception))

    def test_init_with_dict_raises_error(self):
        """Test that OneOf initialization with dict raises FieldDefinitionInvalid"""
        with self.assertRaises(FieldDefinitionInvalid) as context:
            OneOf("valid", {"not": "valid"})  # type: ignore[arg-type]

        self.assertIn("invalid 'OneOf' construct", str(context.exception))


class TestOneOfCast(unittest.TestCase):
    """Test cases for OneOf.cast() method"""

    def test_cast_none_returns_none(self):
        """Test that casting None returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.cast(None)

        self.assertIsNone(result)

    def test_cast_empty_string_returns_none(self):
        """Test that casting empty string returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.cast("")

        self.assertIsNone(result)

    def test_cast_exact_string_literal(self):
        """Test casting exact string literal match"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.cast("successful")

        self.assertEqual(result, "successful")

    def test_cast_case_insensitive_string_literal(self):
        """Test casting case-insensitive string literal match"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.cast("SUCCESSFUL")

        # Should return the canonical form
        self.assertEqual(result, "successful")

    def test_cast_int_literal(self):
        """Test casting integer literal"""
        one_of = OneOf(1, 2, 3)
        result = one_of.cast(2)

        self.assertEqual(result, 2)

    def test_cast_float_literal(self):
        """Test casting float literal"""
        one_of = OneOf(1.0, 2.5, 3.7)
        result = one_of.cast(2.5)

        self.assertEqual(result, 2.5)

    def test_cast_with_model_type(self):
        """Test casting with ModelType"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        result = one_of.cast("mock_castable")
        self.assertEqual(result, "mock_casted")

    def test_cast_model_type_fallback_to_literal(self):
        """Test that casting falls back to literal if ModelType fails"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        result = one_of.cast("disabled")
        self.assertEqual(result, "disabled")

    def test_cast_invalid_value_raises_type_error(self):
        """Test that casting invalid value raises TypeError"""
        one_of = OneOf("pending", "successful", "failed")

        with self.assertRaises(TypeError) as context:
            one_of.cast("invalid_status")

        self.assertIn("not allowable by 'OneOf' definition", str(context.exception))

    def test_cast_tries_all_permitted_types(self):
        """Test that cast tries all permitted types in order"""
        mock_type1 = MockModelType()
        mock_type2 = MockModelType()
        one_of = OneOf(mock_type1, mock_type2, "literal")

        # Should try mock_type1, fail, then mock_type2, fail, then match literal
        result = one_of.cast("literal")
        self.assertEqual(result, "literal")


class TestOneOfRender(unittest.TestCase):
    """Test cases for OneOf.render() method"""

    def test_render_none_returns_none(self):
        """Test that rendering None returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.render(None)

        self.assertIsNone(result)

    def test_render_empty_string_returns_none(self):
        """Test that rendering empty string returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.render("")

        self.assertIsNone(result)

    def test_render_literal(self):
        """Test rendering literal value"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.render("successful")

        self.assertEqual(result, "successful")

    def test_render_with_model_type(self):
        """Test rendering with ModelType"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        result = one_of.render("mock_renderable")
        self.assertEqual(result, "mock_rendered")

    def test_render_model_type_fallback_to_literal(self):
        """Test that rendering falls back to literal if ModelType fails"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        result = one_of.render("disabled")
        self.assertEqual(result, "disabled")

    def test_render_invalid_value_raises_value_error(self):
        """Test that rendering invalid value raises ValueError"""
        one_of = OneOf("pending", "successful", "failed")

        with self.assertRaises(ValueError) as context:
            one_of.render("invalid_status")

        self.assertIn("cannot be rendered", str(context.exception))


class TestOneOfDbDumpLoad(unittest.TestCase):
    """Test cases for OneOf.db_dump() and db_load() methods"""

    def setUp(self):
        """Set up mock dialect for testing"""
        self.mock_dialect = MagicMock(spec=Dialect)

    def test_db_dump_none_returns_none(self):
        """Test that db_dump of None returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.db_dump(None, self.mock_dialect)

        self.assertIsNone(result)

    def test_db_dump_empty_string_returns_none(self):
        """Test that db_dump of empty string returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.db_dump("", self.mock_dialect)

        self.assertIsNone(result)

    def test_db_dump_literal(self):
        """Test db_dump of literal value"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.db_dump("successful", self.mock_dialect)

        self.assertEqual(result, "successful")

    def test_db_dump_with_model_type(self):
        """Test db_dump with ModelType"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        result = one_of.db_dump("mock_dumpable", self.mock_dialect)
        self.assertEqual(result, "mock_dumped")

    def test_db_dump_invalid_value_raises_type_error(self):
        """Test that db_dump of invalid value raises TypeError"""
        one_of = OneOf("pending", "successful", "failed")

        with self.assertRaises(TypeError) as context:
            one_of.db_dump("invalid_status", self.mock_dialect)

        self.assertIn("not allowable by 'OneOf' definition", str(context.exception))

    def test_db_load_none_returns_none(self):
        """Test that db_load of None returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.db_load(None, self.mock_dialect)

        self.assertIsNone(result)

    def test_db_load_empty_string_returns_none(self):
        """Test that db_load of empty string returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.db_load("", self.mock_dialect)

        self.assertIsNone(result)

    def test_db_load_exact_string_literal(self):
        """Test db_load exact string literal match"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.db_load("successful", self.mock_dialect)

        self.assertEqual(result, "successful")

    def test_db_load_case_insensitive_string_literal(self):
        """Test db_load case-insensitive string literal match"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.db_load("SUCCESSFUL", self.mock_dialect)

        # Should return the canonical form
        self.assertEqual(result, "successful")

    def test_db_load_with_model_type(self):
        """Test db_load with ModelType"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        result = one_of.db_load("mock_loadable", self.mock_dialect)
        self.assertEqual(result, "mock_loaded")

    def test_db_load_invalid_value_raises_type_error(self):
        """Test that db_load of invalid value raises TypeError"""
        one_of = OneOf("pending", "successful", "failed")

        with self.assertRaises(TypeError) as context:
            one_of.db_load("invalid_status", self.mock_dialect)

        self.assertIn("not allowable by 'OneOf' definition", str(context.exception))


class TestOneOfDaDumpLoad(unittest.TestCase):
    """Test cases for OneOf.da_dump() and da_load() methods"""

    def test_da_dump_none_returns_none(self):
        """Test that da_dump of None returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.da_dump(None)

        self.assertIsNone(result)

    def test_da_dump_empty_string_returns_none(self):
        """Test that da_dump of empty string returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.da_dump("")

        self.assertIsNone(result)

    def test_da_dump_literal(self):
        """Test da_dump of literal value"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.da_dump("successful")

        self.assertEqual(result, "successful")

    def test_da_dump_with_model_type(self):
        """Test da_dump with ModelType"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        result = one_of.da_dump("mock_da_dumpable")
        self.assertEqual(result, "mock_da_dumped")

    def test_da_dump_invalid_value_raises_type_error(self):
        """Test that da_dump of invalid value raises TypeError"""
        one_of = OneOf("pending", "successful", "failed")

        with self.assertRaises(TypeError) as context:
            one_of.da_dump("invalid_status")

        self.assertIn("not allowable by 'OneOf' definition", str(context.exception))

    def test_da_load_none_returns_none(self):
        """Test that da_load of None returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.da_load(None)

        self.assertIsNone(result)

    def test_da_load_empty_string_returns_none(self):
        """Test that da_load of empty string returns None"""
        one_of = OneOf("pending", "successful")
        result = one_of.da_load("")

        self.assertIsNone(result)

    def test_da_load_exact_string_literal(self):
        """Test da_load exact string literal match"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.da_load("successful")

        self.assertEqual(result, "successful")

    def test_da_load_case_insensitive_string_literal(self):
        """Test da_load case-insensitive string literal match"""
        one_of = OneOf("pending", "successful", "failed")
        result = one_of.da_load("SUCCESSFUL")

        # Should return the canonical form
        self.assertEqual(result, "successful")

    def test_da_load_with_model_type(self):
        """Test da_load with ModelType"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        result = one_of.da_load("mock_da_loadable")
        self.assertEqual(result, "mock_da_loaded")

    def test_da_load_invalid_value_raises_type_error(self):
        """Test that da_load of invalid value raises TypeError"""
        one_of = OneOf("pending", "successful", "failed")

        with self.assertRaises(TypeError) as context:
            one_of.da_load("invalid_status")

        self.assertIn("not allowable by 'OneOf' definition", str(context.exception))


class TestOneOfGetDbType(unittest.TestCase):
    """Test cases for OneOf.get_db_type() method"""

    def setUp(self):
        """Set up mock dialect for testing"""
        self.mock_dialect = MagicMock(spec=Dialect)

    def test_get_db_type_with_string_literals(self):
        """Test get_db_type with string literals returns String"""
        one_of = OneOf("pending", "successful", "failed")
        db_type = one_of.get_db_type(self.mock_dialect)

        self.assertIsInstance(db_type, String)

    def test_get_db_type_with_int_literals(self):
        """Test get_db_type with integer literals returns Integer"""
        one_of = OneOf(1, 2, 3)
        db_type = one_of.get_db_type(self.mock_dialect)

        self.assertIsInstance(db_type, Integer)

    def test_get_db_type_with_float_literals(self):
        """Test get_db_type with float literals returns Float"""
        one_of = OneOf(1.0, 2.5, 3.7)
        db_type = one_of.get_db_type(self.mock_dialect)

        self.assertIsInstance(db_type, Float)

    def test_get_db_type_with_model_type(self):
        """Test get_db_type with ModelType returns common ancestor"""
        mock_type = MockModelType()
        one_of = OneOf(mock_type, "disabled")

        db_type = one_of.get_db_type(self.mock_dialect)
        # MockModelType uses String(), so should return String
        self.assertIsInstance(db_type, String)

    def test_get_db_type_with_multiple_model_types(self):
        """Test get_db_type with multiple ModelTypes finds common ancestor"""
        type1 = ModelType(String())
        type2 = ModelType(String())
        one_of = OneOf(type1, type2)

        db_type = one_of.get_db_type(self.mock_dialect)
        self.assertIsInstance(db_type, String)


class TestOneOfLowestCommonAncestor(unittest.TestCase):
    """Test cases for OneOf._lowest_common_ancestor() method"""

    def test_lca_with_same_class(self):
        """Test _lowest_common_ancestor with same class"""
        one_of = OneOf("a", "b")
        lca = one_of._lowest_common_ancestor(["string1", "string2", "string3"])

        self.assertEqual(lca, str)

    def test_lca_with_numeric_types(self):
        """Test _lowest_common_ancestor with numeric types"""
        one_of = OneOf(1, 2)
        lca = one_of._lowest_common_ancestor([1, 2, 3])

        self.assertEqual(lca, int)

    def test_lca_with_mixed_numeric_types(self):
        """Test _lowest_common_ancestor with mixed int and float"""
        one_of = OneOf(1, 2.0)
        lca = one_of._lowest_common_ancestor([1, 2.0])

        # Should find common ancestor (float is subclass of object, int too)
        # The implementation finds the most specific common class
        self.assertIsNotNone(lca)

    def test_lca_with_class_instances(self):
        """Test _lowest_common_ancestor handles both classes and instances"""
        one_of = OneOf("a")

        # Mix of instances and classes
        lca = one_of._lowest_common_ancestor([str, "instance"])
        self.assertEqual(lca, str)

    def test_lca_with_empty_list(self):
        """Test _lowest_common_ancestor with empty list returns None"""
        one_of = OneOf("a")
        lca = one_of._lowest_common_ancestor([])

        self.assertIsNone(lca)


class TestOneOfGenerateErrorMsg(unittest.TestCase):
    """Test cases for OneOf.generate_error_msg() method"""

    def test_generate_error_msg(self):
        """Test that generate_error_msg returns correct message"""
        one_of = OneOf("pending", "successful", "failed")
        msg = one_of.generate_error_msg("any_value")

        self.assertEqual(msg, "is not a permitted value")


class TestOneOfProperties(unittest.TestCase):
    """Test cases for OneOf properties"""

    def test_permitted_property_returns_copy(self):
        """Test that permitted property returns a copy of the list"""
        one_of = OneOf("pending", "successful", "failed")

        permitted1 = one_of.permitted
        permitted2 = one_of.permitted

        # Should be equal but not the same object
        self.assertEqual(permitted1, permitted2)
        self.assertIsNot(permitted1, permitted2)

    def test_permitted_property_modification_does_not_affect_original(self):
        """Test that modifying returned permitted list doesn't affect original"""
        one_of = OneOf("pending", "successful", "failed")

        permitted = one_of.permitted
        permitted.append("new_value")

        # Original should be unchanged
        self.assertEqual(len(one_of.permitted), 3)
        self.assertNotIn("new_value", one_of.permitted)

    def test_native_type_property_returns_none(self):
        """Test that native_type property returns None"""
        one_of = OneOf("pending", "successful", "failed")

        self.assertIsNone(one_of.native_type)


class TestOneOfEdgeCases(unittest.TestCase):
    """Test cases for OneOf edge cases and special scenarios"""

    def test_cast_with_first_model_type_succeeding(self):
        """Test that cast returns first successful ModelType cast"""
        mock_type1 = MockModelType()
        mock_type2 = MagicMock(spec=ModelType)
        mock_type2.cast.return_value = "should_not_reach_here"

        one_of = OneOf(mock_type1, mock_type2)

        result = one_of.cast("mock_castable")
        self.assertEqual(result, "mock_casted")
        # Second type's cast should not be called
        mock_type2.cast.assert_not_called()

    def test_render_with_first_model_type_succeeding(self):
        """Test that render returns first successful ModelType render"""
        mock_type1 = MockModelType()
        mock_type2 = MagicMock(spec=ModelType)
        mock_type2.render.return_value = "should_not_reach_here"

        one_of = OneOf(mock_type1, mock_type2)

        result = one_of.render("mock_renderable")
        self.assertEqual(result, "mock_rendered")
        # Second type's render should not be called
        mock_type2.render.assert_not_called()

    def test_mixed_types_order_matters(self):
        """Test that order of permitted types matters for casting"""
        # String ModelType should be tried before string literal
        string_type = ModelType(String())
        one_of = OneOf(string_type, "literal")

        # Any string will match the String ModelType first
        result = one_of.cast("any_string")
        self.assertEqual(result, "any_string")


if __name__ == "__main__":
    unittest.main()
