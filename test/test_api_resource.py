"""
Unit tests for keylime.web.base.api_messages.api_resource module
"""

import unittest
from types import MappingProxyType
from unittest.mock import patch

from keylime.web.base.api_messages.api_links import APILink
from keylime.web.base.api_messages.api_meta import APIMeta
from keylime.web.base.api_messages.api_resource import APIResource
from keylime.web.base.exceptions import InvalidMember, MissingMember, UnexpectedMember


class TestAPIResourceLoad(unittest.TestCase):
    """Test cases for APIResource.load() classmethod"""

    def test_load_with_type_only(self):
        """Test loading resource with only type"""
        data = {"type": "agents"}

        resource = APIResource.load(data)

        self.assertEqual(resource.type, "agents")
        self.assertIsNone(resource.id)

    def test_load_with_type_and_id(self):
        """Test loading resource with type and id"""
        data = {"type": "agents", "id": "agent-123"}

        resource = APIResource.load(data)

        self.assertEqual(resource.type, "agents")
        self.assertEqual(resource.id, "agent-123")

    def test_load_with_type_and_attributes(self):
        """Test loading resource with type and attributes"""
        data = {"type": "agents", "attributes": {"name": "Alice", "active": True}}

        resource = APIResource.load(data)

        self.assertEqual(resource.type, "agents")
        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object
        self.assertEqual(attributes["active"], True)  # pylint: disable=unsubscriptable-object

    def test_load_with_all_fields(self):
        """Test loading resource with all fields"""
        data = {
            "type": "agents",
            "id": "agent-123",
            "attributes": {"name": "Alice"},
            "links": {"self": "http://example.com/agents/agent-123"},
            "meta": {"version": "1.0"},
        }

        resource = APIResource.load(data)

        self.assertEqual(resource.type, "agents")
        self.assertEqual(resource.id, "agent-123")
        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object
        self.assertIn("self", resource.links)
        self.assertIn("version", resource.meta)

    def test_load_with_non_mapping_raises_error(self):
        """Test that loading non-mapping raises InvalidMember"""
        with self.assertRaises(InvalidMember) as context:
            APIResource.load("not a mapping")  # type: ignore[arg-type]

        self.assertIn("cannot load object of type", str(context.exception))

    def test_load_with_unexpected_members_raises_error(self):
        """Test that loading with unexpected members raises UnexpectedMember"""
        data = {"type": "agents", "unexpected_field": "value"}

        with self.assertRaises(UnexpectedMember) as context:
            APIResource.load(data)

        self.assertIn("unexpected members", str(context.exception))


class TestAPIResourceInitialization(unittest.TestCase):
    """Test cases for APIResource initialization"""

    def test_init_with_type_only(self):
        """Test APIResource initialization with only type"""
        resource = APIResource("agents")

        self.assertEqual(resource.type, "agents")
        self.assertIsNone(resource.id)
        self.assertEqual(len(resource.attributes), 0)

    def test_init_with_type_and_id(self):
        """Test APIResource initialization with type and id"""
        resource = APIResource("agents", "agent-123")

        self.assertEqual(resource.type, "agents")
        self.assertEqual(resource.id, "agent-123")

    def test_init_with_type_and_attributes(self):
        """Test APIResource initialization with type and attributes"""
        resource = APIResource("agents", {"name": "Alice", "active": True})

        self.assertEqual(resource.type, "agents")
        self.assertIsNone(resource.id)
        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object
        self.assertEqual(attributes["active"], True)  # pylint: disable=unsubscriptable-object

    def test_init_with_type_id_and_attributes(self):
        """Test APIResource initialization with type, id, and attributes"""
        resource = APIResource("agents", "agent-123", {"name": "Alice"})

        self.assertEqual(resource.type, "agents")
        self.assertEqual(resource.id, "agent-123")
        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object

    def test_init_without_args_raises_error(self):
        """Test that APIResource initialization without arguments raises MissingMember"""
        with self.assertRaises(MissingMember) as context:
            APIResource()  # type: ignore[call-overload]

        self.assertIn("no 'type' given", str(context.exception))

    @patch("keylime.web.base.api_messages.api_message_helpers.APIMessageHelpers.is_valid_name")
    def test_init_with_invalid_type_raises_error(self, mock_is_valid):
        """Test that APIResource initialization with invalid type raises InvalidMember"""
        mock_is_valid.return_value = False

        with self.assertRaises(InvalidMember) as context:
            APIResource("invalid@type")

        self.assertIn("invalid 'type'", str(context.exception))

    def test_init_with_invalid_args_raises_error(self):
        """Test that APIResource initialization with invalid arguments raises TypeError"""
        # When second arg is not string and third arg is not dict,
        # it matches (res_id, attributes) case but load_attributes validates first
        with self.assertRaises(TypeError) as context:
            APIResource("agents", 123, "invalid")  # type: ignore[call-overload]

        self.assertIn("must be a mapping", str(context.exception))


class TestAPIResourceSetType(unittest.TestCase):
    """Test cases for APIResource.set_type() method"""

    def test_set_type(self):
        """Test setting type"""
        resource = APIResource("initial_type")
        result = resource.set_type("updated_type")

        self.assertEqual(resource.type, "updated_type")
        self.assertIs(result, resource)  # Should return self for chaining

    @patch("keylime.web.base.api_messages.api_message_helpers.APIMessageHelpers.is_valid_name")
    def test_set_type_with_invalid_name_raises_error(self, mock_is_valid):
        """Test that set_type with invalid name raises InvalidMember"""
        resource = APIResource("initial_type")
        mock_is_valid.return_value = False

        with self.assertRaises(InvalidMember) as context:
            resource.set_type("invalid@type")

        self.assertIn("invalid 'type'", str(context.exception))


class TestAPIResourceSetId(unittest.TestCase):
    """Test cases for APIResource.set_id() and clear_id() methods"""

    def test_set_id(self):
        """Test setting id"""
        resource = APIResource("agents")
        result = resource.set_id("agent-123")

        self.assertEqual(resource.id, "agent-123")
        self.assertIs(result, resource)  # Should return self for chaining

    def test_set_id_with_non_string_raises_error(self):
        """Test that set_id with non-string raises InvalidMember"""
        resource = APIResource("agents")

        with self.assertRaises(InvalidMember) as context:
            resource.set_id(123)  # type: ignore[arg-type]

        self.assertIn("must be a string", str(context.exception))

    def test_set_id_with_empty_string_raises_error(self):
        """Test that set_id with empty string raises InvalidMember"""
        resource = APIResource("agents")

        with self.assertRaises(InvalidMember) as context:
            resource.set_id("")

        self.assertIn("cannot set 'id'", str(context.exception))

    def test_clear_id(self):
        """Test clearing id"""
        resource = APIResource("agents", "agent-123")

        result = resource.clear_id()

        self.assertIsNone(resource.id)
        self.assertIs(result, resource)  # Should return self for chaining


class TestAPIResourceAddAttribute(unittest.TestCase):
    """Test cases for APIResource.add_attribute() method"""

    def test_add_attribute_string(self):
        """Test adding string attribute"""
        resource = APIResource("agents")
        result = resource.add_attribute("name", "Alice")

        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object
        self.assertIs(result, resource)  # Should return self for chaining

    def test_add_attribute_int(self):
        """Test adding int attribute"""
        resource = APIResource("agents")
        resource.add_attribute("count", 42)

        attributes = resource.attributes
        self.assertEqual(attributes["count"], 42)  # pylint: disable=unsubscriptable-object

    def test_add_attribute_float(self):
        """Test adding float attribute"""
        resource = APIResource("agents")
        resource.add_attribute("score", 3.14)

        attributes = resource.attributes
        self.assertEqual(attributes["score"], 3.14)  # pylint: disable=unsubscriptable-object

    def test_add_attribute_bool(self):
        """Test adding bool attribute"""
        resource = APIResource("agents")
        resource.add_attribute("active", True)

        attributes = resource.attributes
        self.assertEqual(attributes["active"], True)  # pylint: disable=unsubscriptable-object

    def test_add_attribute_dict(self):
        """Test adding dict attribute"""
        resource = APIResource("agents")
        resource.add_attribute("config", {"key": "value"})

        attributes = resource.attributes
        self.assertEqual(attributes["config"], {"key": "value"})  # pylint: disable=unsubscriptable-object

    def test_add_attribute_list(self):
        """Test adding list attribute"""
        resource = APIResource("agents")
        resource.add_attribute("tags", ["tag1", "tag2"])

        attributes = resource.attributes
        self.assertEqual(attributes["tags"], ["tag1", "tag2"])  # pylint: disable=unsubscriptable-object

    def test_add_attribute_tuple(self):
        """Test adding tuple attribute"""
        resource = APIResource("agents")
        resource.add_attribute("coords", (1, 2, 3))

        attributes = resource.attributes
        self.assertEqual(attributes["coords"], (1, 2, 3))  # pylint: disable=unsubscriptable-object

    @patch("keylime.web.base.api_messages.api_message_helpers.APIMessageHelpers.is_valid_name")
    def test_add_attribute_with_invalid_name_raises_error(self, mock_is_valid):
        """Test that add_attribute with invalid name raises InvalidMember"""
        resource = APIResource("agents")
        mock_is_valid.return_value = False

        with self.assertRaises(InvalidMember) as context:
            resource.add_attribute("invalid@name", "value")

        self.assertIn("attribute name", str(context.exception))

    def test_add_attribute_with_non_serializable_value_raises_error(self):
        """Test that add_attribute with non-serializable value raises InvalidMember"""
        resource = APIResource("agents")

        class CustomObject:
            pass

        with self.assertRaises(InvalidMember) as context:
            resource.add_attribute("custom", CustomObject())

        self.assertIn("not serialisable to JSON", str(context.exception))

    def test_add_attribute_duplicate_raises_error(self):
        """Test that adding duplicate attribute raises KeyError"""
        resource = APIResource("agents")
        resource.add_attribute("name", "Alice")

        with self.assertRaises(KeyError) as context:
            resource.add_attribute("name", "Bob")

        self.assertIn("already exists", str(context.exception))


class TestAPIResourceLoadAttributes(unittest.TestCase):
    """Test cases for APIResource.load_attributes() method"""

    def test_load_attributes_single(self):
        """Test loading single attribute"""
        resource = APIResource("agents")
        result = resource.load_attributes({"name": "Alice"})

        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object
        self.assertIs(result, resource)

    def test_load_attributes_multiple(self):
        """Test loading multiple attributes"""
        resource = APIResource("agents")
        resource.load_attributes({"name": "Alice", "active": True, "count": 42})

        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object
        self.assertEqual(attributes["active"], True)  # pylint: disable=unsubscriptable-object
        self.assertEqual(attributes["count"], 42)  # pylint: disable=unsubscriptable-object

    def test_load_attributes_with_id_sets_id(self):
        """Test that load_attributes with 'id' key sets resource id"""
        resource = APIResource("agents")
        resource.load_attributes({"id": "agent-123", "name": "Alice"})

        self.assertEqual(resource.id, "agent-123")
        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object
        # 'id' should not be in attributes
        self.assertNotIn("id", attributes)

    def test_load_attributes_with_non_mapping_raises_error(self):
        """Test that load_attributes with non-mapping raises TypeError"""
        resource = APIResource("agents")

        with self.assertRaises(TypeError) as context:
            resource.load_attributes("not a mapping")  # type: ignore[arg-type]

        self.assertIn("must be a mapping", str(context.exception))


class TestAPIResourceRemoveAttribute(unittest.TestCase):
    """Test cases for APIResource.remove_attribute() and clear_attributes() methods"""

    def test_remove_attribute(self):
        """Test removing attribute"""
        resource = APIResource("agents")
        resource.add_attribute("name", "Alice")
        resource.add_attribute("active", True)

        result = resource.remove_attribute("name")

        attributes = resource.attributes
        self.assertNotIn("name", attributes)
        self.assertIn("active", attributes)
        self.assertIs(result, resource)

    def test_remove_attribute_nonexistent_raises_error(self):
        """Test that removing nonexistent attribute raises KeyError"""
        resource = APIResource("agents")

        with self.assertRaises(KeyError) as context:
            resource.remove_attribute("nonexistent")

        self.assertIn("does not exist", str(context.exception))

    def test_clear_attributes(self):
        """Test clearing all attributes"""
        resource = APIResource("agents")
        resource.add_attribute("name", "Alice")
        resource.add_attribute("active", True)

        result = resource.clear_attributes()

        self.assertEqual(len(resource.attributes), 0)
        self.assertIs(result, resource)


class TestAPIResourceInclude(unittest.TestCase):
    """Test cases for APIResource.include() method"""

    def test_include_single_link(self):
        """Test including single APILink"""
        resource = APIResource("agents")
        link = APILink("self", "http://example.com/agents")

        result = resource.include(link)

        self.assertIn("self", resource.links)
        self.assertIs(result, resource)

    def test_include_multiple_links(self):
        """Test including multiple APILinks"""
        resource = APIResource("agents")
        link1 = APILink("self", "http://example.com/agents")
        link2 = APILink("related", "http://example.com/related")

        result = resource.include(link1, link2)

        self.assertIn("self", resource.links)
        self.assertIn("related", resource.links)
        self.assertIs(result, resource)

    def test_include_single_meta(self):
        """Test including single APIMeta"""
        resource = APIResource("agents")
        meta = APIMeta("version", "1.0")

        result = resource.include(meta)

        self.assertIn("version", resource.meta)
        self.assertIs(result, resource)

    def test_include_multiple_meta(self):
        """Test including multiple APIMeta"""
        resource = APIResource("agents")
        meta1 = APIMeta("version", "1.0")
        meta2 = APIMeta("count", 42)

        result = resource.include(meta1, meta2)

        self.assertIn("version", resource.meta)
        self.assertIn("count", resource.meta)
        self.assertIs(result, resource)

    def test_include_link_and_meta(self):
        """Test including both APILink and APIMeta"""
        resource = APIResource("agents")
        link = APILink("self", "http://example.com/agents")
        meta = APIMeta("version", "1.0")

        resource.include(link, meta)

        self.assertIn("self", resource.links)
        self.assertIn("version", resource.meta)

    def test_include_invalid_type_raises_error(self):
        """Test that include with invalid type raises TypeError"""
        resource = APIResource("agents")

        with self.assertRaises(TypeError) as context:
            resource.include("not a link or meta")  # type: ignore[arg-type]

        self.assertIn("cannot add item", str(context.exception))


class TestAPIResourceRender(unittest.TestCase):
    """Test cases for APIResource.render() method"""

    def test_render_type_only(self):
        """Test rendering resource with only type"""
        resource = APIResource("agents")

        rendered = resource.render()

        self.assertEqual(rendered, {"type": "agents"})

    def test_render_with_id(self):
        """Test rendering resource with id"""
        resource = APIResource("agents", "agent-123")

        rendered = resource.render()

        self.assertEqual(rendered["type"], "agents")
        self.assertEqual(rendered["id"], "agent-123")

    def test_render_with_attributes(self):
        """Test rendering resource with attributes"""
        resource = APIResource("agents", {"name": "Alice", "active": True})

        rendered = resource.render()

        self.assertEqual(rendered["type"], "agents")
        self.assertEqual(rendered["attributes"], {"name": "Alice", "active": True})

    def test_render_with_all_fields(self):
        """Test rendering resource with all fields"""
        resource = APIResource("agents", "agent-123", {"name": "Alice"})
        resource.include(
            APILink("self", "http://example.com/agents/agent-123"),
            APIMeta("version", "1.0"),
        )

        rendered = resource.render()

        self.assertEqual(rendered["type"], "agents")
        self.assertEqual(rendered["id"], "agent-123")
        self.assertEqual(rendered["attributes"], {"name": "Alice"})
        self.assertIn("links", rendered)
        self.assertIn("meta", rendered)

    def test_render_attributes_returns_copy(self):
        """Test that render returns a copy of attributes, not reference"""
        resource = APIResource("agents", {"name": "Alice"})

        rendered = resource.render()
        rendered["attributes"]["name"] = "Bob"

        # Original should be unchanged
        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object


class TestAPIResourceProperties(unittest.TestCase):
    """Test cases for APIResource properties"""

    def test_type_property(self):
        """Test type property"""
        resource = APIResource("agents")

        self.assertEqual(resource.type, "agents")

    def test_id_property(self):
        """Test id property"""
        resource = APIResource("agents", "agent-123")

        self.assertEqual(resource.id, "agent-123")

    def test_id_property_none_when_not_set(self):
        """Test id property returns None when not set"""
        resource = APIResource("agents")

        self.assertIsNone(resource.id)

    def test_attributes_property_returns_immutable_copy(self):
        """Test that attributes property returns an immutable MappingProxyType"""
        resource = APIResource("agents", {"name": "Alice"})

        attributes1 = resource.attributes
        attributes2 = resource.attributes

        # Should be immutable (MappingProxyType)
        self.assertIsInstance(attributes1, MappingProxyType)
        # Each access creates new MappingProxyType
        self.assertIsNot(attributes1, attributes2)


class TestAPIResourceBuilderPattern(unittest.TestCase):
    """Test cases for APIResource builder pattern (method chaining)"""

    def test_method_chaining(self):
        """Test that methods can be chained"""
        resource = (
            APIResource("agents")
            .set_id("agent-123")
            .add_attribute("name", "Alice")
            .add_attribute("active", True)
            .include(APILink("self", "http://example.com/agents/agent-123"))
        )

        self.assertEqual(resource.type, "agents")
        self.assertEqual(resource.id, "agent-123")
        attributes = resource.attributes
        self.assertEqual(attributes["name"], "Alice")  # pylint: disable=unsubscriptable-object
        self.assertEqual(attributes["active"], True)  # pylint: disable=unsubscriptable-object
        self.assertIn("self", resource.links)

    def test_clear_methods_chainable(self):
        """Test that clear methods can be chained"""
        resource = APIResource("agents", "agent-123", {"name": "Alice"})

        resource.clear_id().clear_attributes()

        self.assertEqual(resource.type, "agents")
        self.assertIsNone(resource.id)
        self.assertEqual(len(resource.attributes), 0)


if __name__ == "__main__":
    unittest.main()
