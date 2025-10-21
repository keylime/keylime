"""
Unit tests for keylime.web.base.api_messages.api_error module
"""

import unittest
from types import MappingProxyType
from unittest.mock import patch

from keylime.web.base.api_messages.api_error import APIError
from keylime.web.base.api_messages.api_links import APILink
from keylime.web.base.exceptions import InvalidMember, MissingMember


class TestAPIErrorInitialization(unittest.TestCase):
    """Test cases for APIError initialization"""

    def test_init_with_api_code_only(self):
        """Test APIError initialization with only api_code"""
        error = APIError("test_error")

        self.assertEqual(error.api_code, "test_error")
        self.assertIsNone(error.http_code)
        self.assertIsNone(error.detail)
        self.assertIsNone(error.source)

    def test_init_with_api_code_and_http_code(self):
        """Test APIError initialization with api_code and http_code"""
        error = APIError("test_error", 400)

        self.assertEqual(error.api_code, "test_error")
        self.assertEqual(error.http_code, 400)
        self.assertIsNone(error.detail)

    def test_init_with_api_code_and_detail(self):
        """Test APIError initialization with api_code and detail"""
        error = APIError("test_error", "This is a test error")

        self.assertEqual(error.api_code, "test_error")
        self.assertEqual(error.detail, "This is a test error")
        self.assertIsNone(error.http_code)

    def test_init_with_all_parameters(self):
        """Test APIError initialization with api_code, http_code, and detail"""
        error = APIError("test_error", 400, "This is a test error")

        self.assertEqual(error.api_code, "test_error")
        self.assertEqual(error.http_code, 400)
        self.assertEqual(error.detail, "This is a test error")

    def test_init_without_args_raises_error(self):
        """Test that APIError initialization without arguments raises MissingMember"""
        with self.assertRaises(MissingMember) as context:
            APIError()  # type: ignore[call-overload]

        self.assertIn("error code", str(context.exception))
        self.assertIn("must not be empty", str(context.exception))

    @patch("keylime.web.base.api_messages.api_message_helpers.APIMessageHelpers.is_valid_name")
    def test_init_with_invalid_api_code_raises_error(self, mock_is_valid):
        """Test that APIError initialization with invalid api_code raises InvalidMember"""
        mock_is_valid.return_value = False

        with self.assertRaises(InvalidMember) as context:
            APIError("invalid@code")

        self.assertIn("not a valid JSON:API member name", str(context.exception))

    def test_init_with_invalid_args_raises_error(self):
        """Test that APIError initialization with invalid second argument raises InvalidMember"""
        # When second arg is string but not a valid detail (third arg exists), http_code validation fails first
        with self.assertRaises(InvalidMember) as context:
            APIError("test_error", "not_an_int", "extra_arg")  # type: ignore[call-overload]

        self.assertIn("must be given as an int", str(context.exception))

    def test_init_auto_sets_http_code_for_not_found(self):
        """Test that api_code='not_found' automatically sets http_code to 404"""
        error = APIError("not_found")

        self.assertEqual(error.api_code, "not_found")
        self.assertEqual(error.http_code, 404)

    def test_init_auto_sets_http_code_for_conflict(self):
        """Test that api_code='conflict' automatically sets http_code to 409"""
        error = APIError("conflict")

        self.assertEqual(error.api_code, "conflict")
        self.assertEqual(error.http_code, 409)

    def test_init_auto_sets_http_code_for_invalid_resource_data(self):
        """Test that api_code='invalid_resource_data' automatically sets http_code to 422"""
        error = APIError("invalid_resource_data")

        self.assertEqual(error.api_code, "invalid_resource_data")
        self.assertEqual(error.http_code, 422)

    def test_init_explicit_http_code_not_overridden(self):
        """Test that explicitly provided http_code is not overridden by auto-setting"""
        error = APIError("not_found", 500)

        self.assertEqual(error.api_code, "not_found")
        self.assertEqual(error.http_code, 500)  # Should be 500, not auto-set 404


class TestAPIErrorSetApiCode(unittest.TestCase):
    """Test cases for APIError.set_api_code() method"""

    def test_set_api_code(self):
        """Test setting api_code"""
        error = APIError("initial_error")
        result = error.set_api_code("updated_error")

        self.assertEqual(error.api_code, "updated_error")
        self.assertIs(result, error)  # Should return self for chaining

    def test_set_api_code_auto_sets_http_code_when_none(self):
        """Test that set_api_code auto-sets http_code when not already set"""
        error = APIError("initial_error")
        error.clear_http_code()  # Ensure http_code is None

        error.set_api_code("not_found")

        self.assertEqual(error.http_code, 404)

    def test_set_api_code_does_not_override_existing_http_code(self):
        """Test that set_api_code does not override existing http_code"""
        error = APIError("initial_error", 500)

        error.set_api_code("not_found")

        self.assertEqual(error.http_code, 500)  # Should remain 500, not become 404


class TestAPIErrorSetHttpCode(unittest.TestCase):
    """Test cases for APIError.set_http_code() method"""

    def test_set_http_code(self):
        """Test setting http_code"""
        error = APIError("test_error")
        result = error.set_http_code(400)

        self.assertEqual(error.http_code, 400)
        self.assertIs(result, error)  # Should return self for chaining

    def test_set_http_code_with_zero_raises_error(self):
        """Test that set_http_code with 0 raises InvalidMember"""
        error = APIError("test_error")

        with self.assertRaises(InvalidMember) as context:
            error.set_http_code(0)

        self.assertIn("must not be empty", str(context.exception))

    def test_set_http_code_with_non_int_raises_error(self):
        """Test that set_http_code with non-int raises InvalidMember"""
        error = APIError("test_error")

        with self.assertRaises(InvalidMember) as context:
            error.set_http_code("400")  # type: ignore[arg-type]

        self.assertIn("must be given as an int", str(context.exception))

    def test_set_http_code_below_400_raises_error(self):
        """Test that set_http_code with value < 400 raises InvalidMember"""
        error = APIError("test_error")

        with self.assertRaises(InvalidMember) as context:
            error.set_http_code(399)

        self.assertIn("must be in range 400-599", str(context.exception))

    def test_set_http_code_above_599_raises_error(self):
        """Test that set_http_code with value > 599 raises InvalidMember"""
        error = APIError("test_error")

        with self.assertRaises(InvalidMember) as context:
            error.set_http_code(600)

        self.assertIn("must be in range 400-599", str(context.exception))

    def test_set_http_code_at_boundaries(self):
        """Test set_http_code at valid boundaries (400 and 599)"""
        error = APIError("test_error")

        error.set_http_code(400)
        self.assertEqual(error.http_code, 400)

        error.set_http_code(599)
        self.assertEqual(error.http_code, 599)

    def test_clear_http_code(self):
        """Test clearing http_code"""
        error = APIError("test_error", 400)

        result = error.clear_http_code()

        self.assertIsNone(error.http_code)
        self.assertIs(result, error)  # Should return self for chaining


class TestAPIErrorSetDetail(unittest.TestCase):
    """Test cases for APIError.set_detail() method"""

    def test_set_detail(self):
        """Test setting detail"""
        error = APIError("test_error")
        result = error.set_detail("This is a detailed error message")

        self.assertEqual(error.detail, "This is a detailed error message")
        self.assertIs(result, error)  # Should return self for chaining

    def test_set_detail_with_non_string_raises_error(self):
        """Test that set_detail with non-string raises InvalidMember"""
        error = APIError("test_error")

        with self.assertRaises(InvalidMember) as context:
            error.set_detail(123)  # type: ignore[arg-type]

        self.assertIn("must be a str", str(context.exception))

    def test_set_detail_with_empty_string_raises_error(self):
        """Test that set_detail with empty string raises InvalidMember"""
        error = APIError("test_error")

        with self.assertRaises(InvalidMember) as context:
            error.set_detail("")

        self.assertIn("must not be empty", str(context.exception))

    def test_clear_detail(self):
        """Test clearing detail"""
        error = APIError("test_error", "Initial detail")

        result = error.clear_detail()

        self.assertIsNone(error.detail)
        self.assertIs(result, error)  # Should return self for chaining


class TestAPIErrorSetSource(unittest.TestCase):
    """Test cases for APIError.set_source() method"""

    def test_set_source_with_pointer(self):
        """Test setting source with pointer"""
        error = APIError("test_error")
        result = error.set_source(pointer="/data/attributes/email")

        assert error.source is not None
        source = error.source
        self.assertEqual(source["pointer"], "/data/attributes/email")  # pylint: disable=unsubscriptable-object
        self.assertIs(result, error)  # Should return self for chaining

    def test_set_source_with_parameter(self):
        """Test setting source with parameter"""
        error = APIError("test_error")
        result = error.set_source(parameter="email")

        assert error.source is not None
        source = error.source
        self.assertEqual(source["parameter"], "email")  # pylint: disable=unsubscriptable-object
        self.assertIs(result, error)

    def test_set_source_with_header(self):
        """Test setting source with header"""
        error = APIError("test_error")
        result = error.set_source(header="Authorization")

        assert error.source is not None
        source = error.source
        self.assertEqual(source["header"], "Authorization")  # pylint: disable=unsubscriptable-object
        self.assertIs(result, error)

    def test_set_source_with_invalid_kwarg_raises_error(self):
        """Test that set_source with invalid kwargs raises TypeError"""
        error = APIError("test_error")

        with self.assertRaises(TypeError) as context:
            error.set_source(invalid_kwarg="value")  # type: ignore[call-arg]

        self.assertIn("invalid keyword arguments", str(context.exception))

    def test_clear_source(self):
        """Test clearing source"""
        error = APIError("test_error")
        error.set_source(pointer="/data/attributes/email")

        result = error.clear_source()

        self.assertIsNone(error.source)
        self.assertIs(result, error)  # Should return self for chaining

    def test_source_property_returns_immutable_copy(self):
        """Test that source property returns an immutable MappingProxyType"""
        error = APIError("test_error")
        error.set_source(pointer="/data/attributes/email")

        source1 = error.source
        source2 = error.source

        assert source1 is not None
        assert source2 is not None
        # Should be immutable (MappingProxyType)
        self.assertIsInstance(source1, MappingProxyType)
        # Each access creates new MappingProxyType
        self.assertIsNot(source1, source2)


class TestAPIErrorInclude(unittest.TestCase):
    """Test cases for APIError.include() method"""

    def test_include_single_link(self):
        """Test including single APILink"""
        error = APIError("test_error")
        link = APILink("about", "https://example.com/errors/test_error")

        result = error.include(link)

        self.assertIn("about", error.links)
        self.assertIs(result, error)  # Should return self for chaining

    def test_include_multiple_links(self):
        """Test including multiple APILinks"""
        error = APIError("test_error")
        link1 = APILink("about", "https://example.com/errors/test_error")
        link2 = APILink("related", "https://example.com/related")

        result = error.include(link1, link2)

        self.assertIn("about", error.links)
        self.assertIn("related", error.links)
        self.assertIs(result, error)

    def test_include_non_link_raises_error(self):
        """Test that include with non-APILink raises TypeError"""
        error = APIError("test_error")

        with self.assertRaises(TypeError) as context:
            error.include("not_a_link")  # type: ignore[arg-type]

        self.assertIn("cannot add item", str(context.exception))


class TestAPIErrorRender(unittest.TestCase):
    """Test cases for APIError.render() method"""

    def test_render_minimal_error(self):
        """Test rendering error with only api_code"""
        error = APIError("test_error")
        error.clear_http_code()  # Ensure no auto-set http_code

        rendered = error.render()

        self.assertEqual(rendered, {"code": "test_error"})

    def test_render_with_http_code(self):
        """Test rendering error with http_code"""
        error = APIError("test_error", 400)

        rendered = error.render()

        self.assertEqual(rendered["status"], "400")
        self.assertEqual(rendered["code"], "test_error")

    def test_render_with_detail(self):
        """Test rendering error with detail"""
        error = APIError("test_error", "This is a test error")

        rendered = error.render()

        self.assertEqual(rendered["code"], "test_error")
        self.assertEqual(rendered["detail"], "This is a test error")

    def test_render_with_all_fields(self):
        """Test rendering error with all fields"""
        error = APIError("test_error", 400, "This is a test error")
        error.set_source(pointer="/data/attributes/email")
        link = APILink("about", "https://example.com/errors")
        error.include(link)

        rendered = error.render()

        self.assertEqual(rendered["status"], "400")
        self.assertEqual(rendered["code"], "test_error")
        self.assertEqual(rendered["detail"], "This is a test error")
        self.assertEqual(rendered["source"], {"pointer": "/data/attributes/email"})
        self.assertIn("links", rendered)
        self.assertIn("about", rendered["links"])

    def test_render_http_code_as_string(self):
        """Test that render converts http_code to string"""
        error = APIError("test_error", 404)

        rendered = error.render()

        self.assertIsInstance(rendered["status"], str)
        self.assertEqual(rendered["status"], "404")


class TestAPIErrorProperties(unittest.TestCase):
    """Test cases for APIError properties"""

    def test_api_code_property(self):
        """Test api_code property"""
        error = APIError("test_error")

        self.assertEqual(error.api_code, "test_error")

    def test_http_code_property(self):
        """Test http_code property"""
        error = APIError("test_error", 400)

        self.assertEqual(error.http_code, 400)

    def test_detail_property(self):
        """Test detail property"""
        error = APIError("test_error", "This is a test error")

        self.assertEqual(error.detail, "This is a test error")

    def test_source_property_none_when_not_set(self):
        """Test source property returns None when not set"""
        error = APIError("test_error")

        self.assertIsNone(error.source)


class TestAPIErrorBuilderPattern(unittest.TestCase):
    """Test cases for APIError builder pattern (method chaining)"""

    def test_method_chaining(self):
        """Test that methods can be chained"""
        error = (
            APIError("test_error")
            .set_http_code(400)
            .set_detail("This is a test error")
            .set_source(pointer="/data/attributes/email")
        )

        self.assertEqual(error.api_code, "test_error")
        self.assertEqual(error.http_code, 400)
        self.assertEqual(error.detail, "This is a test error")
        assert error.source is not None
        source = error.source
        self.assertEqual(source["pointer"], "/data/attributes/email")  # pylint: disable=unsubscriptable-object

    def test_clear_methods_chainable(self):
        """Test that clear methods can be chained"""
        error = APIError("test_error", 400, "Detail")
        error.set_source(pointer="/data")

        error.clear_http_code().clear_detail().clear_source()

        self.assertEqual(error.api_code, "test_error")
        self.assertIsNone(error.http_code)
        self.assertIsNone(error.detail)
        self.assertIsNone(error.source)


if __name__ == "__main__":
    unittest.main()
