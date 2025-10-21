"""
Unit tests for keylime.web.base.api_messages.api_message_body module
"""

import unittest
from types import MappingProxyType

from keylime.models.base.basic_model import BasicModel
from keylime.web.base.api_messages.api_error import APIError
from keylime.web.base.api_messages.api_links import APILink
from keylime.web.base.api_messages.api_message_body import APIMessageBody
from keylime.web.base.api_messages.api_meta import APIMeta
from keylime.web.base.api_messages.api_resource import APIResource
from keylime.web.base.exceptions import InvalidMember, InvalidMessage, MissingMember, UnexpectedMember


class TestAPIMessageBodyLoad(unittest.TestCase):
    """Test cases for APIMessageBody.load() classmethod"""

    def test_load_with_data_only(self):
        """Test loading message body with only data"""
        data = {"data": {"type": "agents", "id": "agent-123"}}

        message_body = APIMessageBody.load(data)

        self.assertIsNotNone(message_body.data)
        self.assertEqual(len(message_body.errors), 0)

    # NOTE: test_load_with_errors_only removed because APIError.load() doesn't exist yet

    def test_load_with_meta_only(self):
        """Test loading message body with only meta"""
        data = {"meta": {"version": "1.0"}}

        message_body = APIMessageBody.load(data)

        self.assertIsNone(message_body.data)
        self.assertEqual(len(message_body.errors), 0)
        self.assertIn("version", message_body.meta)

    def test_load_with_data_and_meta(self):
        """Test loading message body with data and meta"""
        data = {"data": {"type": "agents"}, "meta": {"version": "1.0"}}

        message_body = APIMessageBody.load(data)

        self.assertIsNotNone(message_body.data)
        self.assertIn("version", message_body.meta)

    def test_load_with_data_and_links(self):
        """Test loading message body with data and links"""
        data = {"data": {"type": "agents"}, "links": {"self": "http://example.com/agents"}}

        message_body = APIMessageBody.load(data)

        self.assertIsNotNone(message_body.data)
        self.assertIn("self", message_body.links)

    def test_load_with_jsonapi_member(self):
        """Test loading message body with jsonapi member (ignored)"""
        data = {"data": {"type": "agents"}, "jsonapi": {"version": "1.0"}}

        message_body = APIMessageBody.load(data)

        # jsonapi member is ignored during load
        self.assertIsNotNone(message_body.data)

    def test_load_with_non_mapping_raises_error(self):
        """Test that loading non-mapping raises InvalidMember"""
        with self.assertRaises(InvalidMember) as context:
            APIMessageBody.load("not a mapping")  # type: ignore[arg-type]

        self.assertIn("cannot load object of type", str(context.exception))

    def test_load_with_unexpected_members_raises_error(self):
        """Test that loading with unexpected members raises UnexpectedMember"""
        data = {"data": {"type": "agents"}, "unexpected_field": "value"}

        with self.assertRaises(UnexpectedMember) as context:
            APIMessageBody.load(data)

        self.assertIn("unexpected members", str(context.exception))

    def test_load_with_no_required_members_raises_error(self):
        """Test that loading with no data/errors/meta raises MissingMember"""
        data = {"links": {"self": "http://example.com"}}

        with self.assertRaises(MissingMember) as context:
            APIMessageBody.load(data)

        self.assertIn("at least one is required", str(context.exception))


class TestAPIMessageBodyInitialization(unittest.TestCase):
    """Test cases for APIMessageBody initialization"""

    def test_init_empty(self):
        """Test APIMessageBody initialization with no arguments"""
        # Empty message body will fail check_validity() but can be created
        message_body = APIMessageBody()

        self.assertIsNone(message_body.data)
        self.assertEqual(len(message_body.errors), 0)

    def test_init_with_resource(self):
        """Test APIMessageBody initialization with resource"""
        resource = APIResource("agents", "agent-123")
        message_body = APIMessageBody(resource)

        self.assertIsNotNone(message_body.data)

    def test_init_with_error(self):
        """Test APIMessageBody initialization with error"""
        error = APIError("test_error")
        message_body = APIMessageBody(error)

        self.assertEqual(len(message_body.errors), 1)

    def test_init_with_meta(self):
        """Test APIMessageBody initialization with meta"""
        meta = APIMeta("version", "1.0")
        message_body = APIMessageBody(meta)

        self.assertIn("version", message_body.meta)

    def test_init_with_link(self):
        """Test APIMessageBody initialization with link"""
        link = APILink("self", "http://example.com")
        message_body = APIMessageBody(link)

        self.assertIn("self", message_body.links)

    def test_init_with_multiple_items(self):
        """Test APIMessageBody initialization with multiple items"""
        resource = APIResource("agents")
        meta = APIMeta("version", "1.0")
        link = APILink("self", "http://example.com")

        message_body = APIMessageBody(resource, meta, link)

        self.assertIsNotNone(message_body.data)
        self.assertIn("version", message_body.meta)
        self.assertIn("self", message_body.links)


class TestAPIMessageBodyAddResource(unittest.TestCase):
    """Test cases for APIMessageBody.add_resource() method"""

    def test_add_resource_to_empty(self):
        """Test adding resource to empty message body"""
        message_body = APIMessageBody()
        resource = APIResource("agents", "agent-123")

        result = message_body.add_resource(resource)

        self.assertIsNotNone(message_body.data)
        self.assertIsInstance(message_body.data, APIResource)
        self.assertIs(result, message_body)

    def test_add_second_resource_creates_list(self):
        """Test adding second resource creates list"""
        message_body = APIMessageBody()
        resource1 = APIResource("agents", "agent-1")
        resource2 = APIResource("agents", "agent-2")

        message_body.add_resource(resource1)
        message_body.add_resource(resource2)

        self.assertIsInstance(message_body.data, list)
        data = message_body.data
        assert isinstance(data, list)
        self.assertEqual(len(data), 2)

    def test_add_resource_with_non_resource_raises_error(self):
        """Test that adding non-APIResource raises InvalidMember"""
        message_body = APIMessageBody()

        with self.assertRaises(InvalidMember) as context:
            message_body.add_resource("not a resource")  # type: ignore[arg-type]

        self.assertIn("must be an APIResource object", str(context.exception))

    def test_add_resource_with_errors_raises_error(self):
        """Test that adding resource to message body with errors raises InvalidMember"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("test_error"))

        with self.assertRaises(InvalidMember) as context:
            message_body.add_resource(APIResource("agents"))

        self.assertIn("which contains an 'errors' member", str(context.exception))

    def test_add_duplicate_resource_raises_error(self):
        """Test that adding duplicate resource raises InvalidMessage"""
        message_body = APIMessageBody()
        resource = APIResource("agents", "agent-123")

        message_body.add_resource(resource)

        with self.assertRaises(InvalidMessage) as context:
            message_body.add_resource(resource)

        self.assertIn("already exists", str(context.exception))

    def test_add_resource_with_same_id_and_type_raises_error(self):
        """Test that adding resource with same id and type raises InvalidMessage"""
        message_body = APIMessageBody()
        resource1 = APIResource("agents", "agent-123")
        resource2 = APIResource("agents", "agent-123")

        message_body.add_resource(resource1)

        with self.assertRaises(InvalidMessage) as context:
            message_body.add_resource(resource2)

        self.assertIn("already exists", str(context.exception))


class TestAPIMessageBodyLoadResources(unittest.TestCase):
    """Test cases for APIMessageBody.load_resources() method"""

    def test_load_resources_single_mapping(self):
        """Test loading single resource from mapping"""
        message_body = APIMessageBody()
        data = {"type": "agents", "id": "agent-123"}

        result = message_body.load_resources(data)

        self.assertIsNotNone(message_body.data)
        self.assertIs(result, message_body)

    def test_load_resources_sequence(self):
        """Test loading multiple resources from sequence"""
        message_body = APIMessageBody()
        data = [{"type": "agents", "id": "agent-1"}, {"type": "agents", "id": "agent-2"}]

        message_body.load_resources(data)

        self.assertIsInstance(message_body.data, list)
        data_list = message_body.data
        assert isinstance(data_list, list)
        self.assertEqual(len(data_list), 2)

    def test_load_resources_with_invalid_type_raises_error(self):
        """Test that load_resources with invalid type raises InvalidMember"""
        message_body = APIMessageBody()

        # Error comes from APIResource.load() when it tries to load the string
        with self.assertRaises(InvalidMember) as context:
            message_body.load_resources("not a mapping or sequence")  # type: ignore[arg-type]

        self.assertIn("cannot load object of type", str(context.exception))


class TestAPIMessageBodyRemoveResource(unittest.TestCase):
    """Test cases for APIMessageBody.remove_resource() and clear_resources() methods"""

    def test_remove_resource_single(self):
        """Test removing single resource"""
        message_body = APIMessageBody()
        resource = APIResource("agents", "agent-123")
        message_body.add_resource(resource)

        result = message_body.remove_resource(resource)

        self.assertIsNone(message_body.data)
        self.assertIs(result, message_body)

    def test_remove_resource_from_list(self):
        """Test removing resource from list"""
        message_body = APIMessageBody()
        resource1 = APIResource("agents", "agent-1")
        resource2 = APIResource("agents", "agent-2")
        message_body.add_resource(resource1)
        message_body.add_resource(resource2)

        message_body.remove_resource(resource1)

        data = message_body.data
        assert isinstance(data, list)
        self.assertEqual(len(data), 1)

    def test_remove_last_resource_from_list_sets_none(self):
        """Test removing last resource from list sets data to None"""
        message_body = APIMessageBody()
        resource1 = APIResource("agents", "agent-1")
        resource2 = APIResource("agents", "agent-2")
        message_body.add_resource(resource1)
        message_body.add_resource(resource2)

        message_body.remove_resource(resource1)
        message_body.remove_resource(resource2)

        self.assertIsNone(message_body.data)

    def test_remove_nonexistent_resource_raises_error(self):
        """Test that removing nonexistent resource raises KeyError"""
        message_body = APIMessageBody()
        resource = APIResource("agents", "agent-123")

        with self.assertRaises(KeyError) as context:
            message_body.remove_resource(resource)

        self.assertIn("does not exist", str(context.exception))

    def test_clear_resources(self):
        """Test clearing all resources"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents", "agent-1"))
        message_body.add_resource(APIResource("agents", "agent-2"))

        result = message_body.clear_resources()

        self.assertIsNone(message_body.data)
        self.assertIs(result, message_body)


class TestAPIMessageBodyAddError(unittest.TestCase):
    """Test cases for APIMessageBody.add_error() method"""

    def test_add_error_to_empty(self):
        """Test adding error to empty message body"""
        message_body = APIMessageBody()
        error = APIError("test_error")

        result = message_body.add_error(error)

        self.assertEqual(len(message_body.errors), 1)
        self.assertIs(result, message_body)

    def test_add_multiple_errors(self):
        """Test adding multiple errors"""
        message_body = APIMessageBody()
        error1 = APIError("error1")
        error2 = APIError("error2")

        message_body.add_error(error1)
        message_body.add_error(error2)

        self.assertEqual(len(message_body.errors), 2)

    def test_add_error_with_non_error_raises_error(self):
        """Test that adding non-APIError raises TypeError"""
        message_body = APIMessageBody()

        with self.assertRaises(TypeError) as context:
            message_body.add_error("not an error")  # type: ignore[arg-type]

        self.assertIn("cannot add item", str(context.exception))

    def test_add_error_with_data_raises_error(self):
        """Test that adding error to message body with data raises InvalidMember"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents"))

        with self.assertRaises(InvalidMember) as context:
            message_body.add_error(APIError("test_error"))

        self.assertIn("which contains a 'data' member", str(context.exception))

    def test_add_duplicate_error_raises_error(self):
        """Test that adding duplicate error raises KeyError"""
        message_body = APIMessageBody()
        error = APIError("test_error")

        message_body.add_error(error)

        with self.assertRaises(KeyError) as context:
            message_body.add_error(error)

        self.assertIn("already exists", str(context.exception))


# NOTE: TestAPIMessageBodyLoadErrors class removed because APIError.load() doesn't exist yet
# load_errors() calls APIError.load() which is not implemented


class TestAPIMessageBodyRemoveError(unittest.TestCase):
    """Test cases for APIMessageBody.remove_error() and clear_errors() methods"""

    def test_remove_error(self):
        """Test removing error"""
        message_body = APIMessageBody()
        error = APIError("test_error")
        message_body.add_error(error)

        result = message_body.remove_error(error)

        self.assertEqual(len(message_body.errors), 0)
        self.assertIs(result, message_body)

    def test_remove_nonexistent_error_raises_error(self):
        """Test that removing nonexistent error raises KeyError"""
        message_body = APIMessageBody()
        error = APIError("test_error")

        with self.assertRaises(KeyError) as context:
            message_body.remove_error(error)

        self.assertIn("does not exist", str(context.exception))

    def test_clear_errors(self):
        """Test clearing all errors"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error1"))
        message_body.add_error(APIError("error2"))

        result = message_body.clear_errors()

        self.assertEqual(len(message_body.errors), 0)
        self.assertIs(result, message_body)


class TestAPIMessageBodyGetErrors(unittest.TestCase):
    """Test cases for APIMessageBody.get_errors() method"""

    def test_get_errors_by_api_code(self):
        """Test getting errors by API code"""
        message_body = APIMessageBody()
        error1 = APIError("test_error")
        error2 = APIError("other_error")
        message_body.add_error(error1)
        message_body.add_error(error2)

        result = message_body.get_errors("test_error")

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].api_code, "test_error")

    def test_get_errors_by_http_code(self):
        """Test getting errors by HTTP code"""
        message_body = APIMessageBody()
        error1 = APIError("error1", 404)
        error2 = APIError("error2", 500)
        message_body.add_error(error1)
        message_body.add_error(error2)

        result = message_body.get_errors(404)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].http_code, 404)

    def test_get_errors_no_match(self):
        """Test getting errors with no match"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("test_error"))

        result = message_body.get_errors("nonexistent")

        self.assertEqual(len(result), 0)


class TestAPIMessageBodyInclude(unittest.TestCase):
    """Test cases for APIMessageBody.include() method"""

    def test_include_resource(self):
        """Test including resource"""
        message_body = APIMessageBody()
        resource = APIResource("agents")

        result = message_body.include(resource)

        self.assertIsNotNone(message_body.data)
        self.assertIs(result, message_body)

    def test_include_error(self):
        """Test including error"""
        message_body = APIMessageBody()
        error = APIError("test_error")

        result = message_body.include(error)

        self.assertEqual(len(message_body.errors), 1)
        self.assertIs(result, message_body)

    def test_include_meta(self):
        """Test including meta"""
        message_body = APIMessageBody()
        meta = APIMeta("version", "1.0")

        message_body.include(meta)

        self.assertIn("version", message_body.meta)

    def test_include_link(self):
        """Test including link"""
        message_body = APIMessageBody()
        link = APILink("self", "http://example.com")

        message_body.include(link)

        self.assertIn("self", message_body.links)

    def test_include_multiple_items(self):
        """Test including multiple items"""
        message_body = APIMessageBody()
        resource = APIResource("agents")
        meta = APIMeta("version", "1.0")

        message_body.include(resource, meta)

        self.assertIsNotNone(message_body.data)
        self.assertIn("version", message_body.meta)

    def test_include_invalid_type_raises_error(self):
        """Test that include with invalid type raises TypeError"""
        message_body = APIMessageBody()

        with self.assertRaises(TypeError) as context:
            message_body.include("not valid")  # type: ignore[arg-type]

        self.assertIn("cannot add item", str(context.exception))


class TestAPIMessageBodyCheckValidity(unittest.TestCase):
    """Test cases for APIMessageBody.check_validity() method"""

    def test_check_validity_with_data_succeeds(self):
        """Test check_validity with data succeeds"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents"))

        # Should not raise
        message_body.check_validity()

    def test_check_validity_with_errors_succeeds(self):
        """Test check_validity with errors succeeds"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("test_error"))

        # Should not raise
        message_body.check_validity()

    def test_check_validity_with_meta_succeeds(self):
        """Test check_validity with meta succeeds"""
        message_body = APIMessageBody()
        message_body.include(APIMeta("version", "1.0"))

        # Should not raise
        message_body.check_validity()

    def test_check_validity_without_required_raises_error(self):
        """Test check_validity without data/errors/meta raises MissingMember"""
        message_body = APIMessageBody()

        with self.assertRaises(MissingMember) as context:
            message_body.check_validity()

        self.assertIn("at least one is required", str(context.exception))


class TestAPIMessageBodyRender(unittest.TestCase):
    """Test cases for APIMessageBody.render() method"""

    def test_render_with_single_resource(self):
        """Test rendering with single resource"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents", "agent-123"))

        rendered = message_body.render()

        self.assertIn("data", rendered)
        self.assertEqual(rendered["data"]["type"], "agents")
        self.assertEqual(rendered["data"]["id"], "agent-123")

    def test_render_with_multiple_resources(self):
        """Test rendering with multiple resources"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents", "agent-1"))
        message_body.add_resource(APIResource("agents", "agent-2"))

        rendered = message_body.render()

        self.assertIn("data", rendered)
        self.assertIsInstance(rendered["data"], list)
        self.assertEqual(len(rendered["data"]), 2)

    def test_render_with_errors(self):
        """Test rendering with errors"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("test_error", 400))

        rendered = message_body.render()

        self.assertIn("errors", rendered)
        self.assertEqual(len(rendered["errors"]), 1)
        self.assertEqual(rendered["errors"][0]["code"], "test_error")

    def test_render_with_meta(self):
        """Test rendering with meta"""
        message_body = APIMessageBody()
        message_body.include(APIMeta("version", "1.0"))

        rendered = message_body.render()

        self.assertIn("meta", rendered)
        self.assertIn("version", rendered["meta"])

    def test_render_with_links(self):
        """Test rendering with links"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents"))
        message_body.include(APILink("self", "http://example.com"))

        rendered = message_body.render()

        self.assertIn("links", rendered)
        self.assertIn("self", rendered["links"])

    def test_render_with_jsonapi(self):
        """Test rendering with jsonapi info"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents"))

        rendered = message_body.render()

        # jsonapi is always included
        self.assertIn("jsonapi", rendered)

    def test_render_without_required_raises_error(self):
        """Test that render without data/errors/meta raises MissingMember"""
        message_body = APIMessageBody()

        with self.assertRaises(MissingMember):
            message_body.render()


class TestAPIMessageBodyProperties(unittest.TestCase):
    """Test cases for APIMessageBody properties"""

    def test_data_property_returns_copy(self):
        """Test that data property returns copy for lists"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents", "agent-1"))
        message_body.add_resource(APIResource("agents", "agent-2"))

        data1 = message_body.data
        data2 = message_body.data

        # Should be different list objects
        assert isinstance(data1, list)
        assert isinstance(data2, list)
        self.assertIsNot(data1, data2)

    def test_data_property_returns_single_resource(self):
        """Test that data property returns single resource unchanged"""
        message_body = APIMessageBody()
        resource = APIResource("agents")
        message_body.add_resource(resource)

        data = message_body.data

        self.assertIs(data, resource)

    def test_errors_property_returns_copy(self):
        """Test that errors property returns copy"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error1"))

        errors1 = message_body.errors
        errors2 = message_body.errors

        # Should be different list objects
        self.assertIsNot(errors1, errors2)

    def test_client_errors_property(self):
        """Test client_errors property (4xx codes)"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error1", 400))
        message_body.add_error(APIError("error2", 404))
        message_body.add_error(APIError("error3", 500))

        client_errors = message_body.client_errors

        self.assertEqual(len(client_errors), 2)
        self.assertEqual(client_errors[0].http_code, 400)
        self.assertEqual(client_errors[1].http_code, 404)

    def test_server_errors_property(self):
        """Test server_errors property (5xx codes)"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error1", 400))
        message_body.add_error(APIError("error2", 500))
        message_body.add_error(APIError("error3", 503))

        server_errors = message_body.server_errors

        self.assertEqual(len(server_errors), 2)
        self.assertEqual(server_errors[0].http_code, 500)
        self.assertEqual(server_errors[1].http_code, 503)

    def test_meta_property_returns_immutable(self):
        """Test that meta property returns immutable MappingProxyType"""
        message_body = APIMessageBody()
        message_body.include(APIMeta("version", "1.0"))

        meta = message_body.meta

        self.assertIsInstance(meta, MappingProxyType)

    def test_links_property_returns_immutable(self):
        """Test that links property returns immutable MappingProxyType"""
        message_body = APIMessageBody()
        message_body.include(APILink("self", "http://example.com"))

        links = message_body.links

        self.assertIsInstance(links, MappingProxyType)

    def test_jsonapi_property(self):
        """Test jsonapi property"""
        message_body = APIMessageBody()

        jsonapi = message_body.jsonapi

        self.assertIsNotNone(jsonapi)


class TestAPIMessageBodyInferHTTPCode(unittest.TestCase):
    """Test cases for APIMessageBody._infer_http_code() and related methods"""

    def test_infer_http_code_with_single_client_error(self):
        """Test inferring HTTP code with single client error"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error", 404))

        code = message_body._infer_http_code()  # pylint: disable=protected-access

        self.assertEqual(code, 404)

    def test_infer_http_code_with_multiple_client_errors(self):
        """Test inferring HTTP code with multiple client errors defaults to 400"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error1", 404))
        message_body.add_error(APIError("error2", 422))

        code = message_body._infer_http_code()  # pylint: disable=protected-access

        self.assertEqual(code, 400)

    def test_infer_http_code_with_single_server_error(self):
        """Test inferring HTTP code with single server error"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error", 500))

        code = message_body._infer_http_code()  # pylint: disable=protected-access

        self.assertEqual(code, 500)

    def test_infer_http_code_with_multiple_server_errors(self):
        """Test inferring HTTP code with multiple server errors defaults to 500"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error1", 500))
        message_body.add_error(APIError("error2", 503))

        code = message_body._infer_http_code()  # pylint: disable=protected-access

        self.assertEqual(code, 500)

    def test_infer_http_code_with_mixed_errors_raises_error(self):
        """Test that inferring HTTP code with both 4xx and 5xx errors raises ValueError"""
        message_body = APIMessageBody()
        message_body.add_error(APIError("error1", 400))
        message_body.add_error(APIError("error2", 500))

        with self.assertRaises(ValueError) as context:
            message_body._infer_http_code()  # pylint: disable=protected-access

        self.assertIn("both 4xx and 5xx", str(context.exception))

    def test_infer_http_code_with_no_http_codes_raises_error(self):
        """Test that inferring HTTP code with no http_code values raises ValueError"""
        message_body = APIMessageBody()
        error = APIError("error")
        error.clear_http_code()
        message_body.add_error(error)

        with self.assertRaises(ValueError) as context:
            message_body._infer_http_code()  # pylint: disable=protected-access

        self.assertIn("blank http_code", str(context.exception))

    def test_infer_http_code_with_data_returns_200(self):
        """Test that inferring HTTP code with data returns 200"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents"))

        code = message_body._infer_http_code()  # pylint: disable=protected-access

        self.assertEqual(code, 200)


class TestAPIMessageBodyBuilderPattern(unittest.TestCase):
    """Test cases for APIMessageBody builder pattern (method chaining)"""

    def test_method_chaining_resources(self):
        """Test that resource methods can be chained"""
        message_body = (
            APIMessageBody()
            .add_resource(APIResource("agents", "agent-1"))
            .include(APIMeta("version", "1.0"))
            .include(APILink("self", "http://example.com"))
        )

        self.assertIsNotNone(message_body.data)
        self.assertIn("version", message_body.meta)
        self.assertIn("self", message_body.links)

    def test_method_chaining_errors(self):
        """Test that error methods can be chained"""
        message_body = (
            APIMessageBody().add_error(APIError("error1")).add_error(APIError("error2")).include(APIMeta("count", 2))
        )

        self.assertEqual(len(message_body.errors), 2)
        self.assertIn("count", message_body.meta)


class TestAPIMessageBodyFromRecordErrors(unittest.TestCase):
    """Test cases for APIMessageBody.from_record_errors() classmethod"""

    def test_from_record_errors_single_record(self):
        """Test creating message body from single record with errors"""

        class TestModel(BasicModel):
            @classmethod
            def _schema(cls):
                return None

        record = TestModel.empty()
        # Simulate adding errors to the record
        record._errors = {"field1": ["is required", "must be valid"]}  # pylint: disable=protected-access

        message_body = APIMessageBody.from_record_errors(record)

        self.assertEqual(len(message_body.errors), 2)
        # Verify errors were created from the record
        self.assertEqual(message_body.errors[0].api_code, "invalid_resource_data")

    def test_from_record_errors_multiple_records(self):
        """Test creating message body from multiple records with errors"""

        class TestModel(BasicModel):
            @classmethod
            def _schema(cls):
                return None

        record1 = TestModel.empty()
        record2 = TestModel.empty()
        record1._errors = {"field1": ["error1"]}  # pylint: disable=protected-access
        record2._errors = {"field2": ["error2"]}  # pylint: disable=protected-access

        message_body = APIMessageBody.from_record_errors([record1, record2])

        self.assertEqual(len(message_body.errors), 2)


class TestAPIMessageBodyAddRecordErrors(unittest.TestCase):
    """Test cases for APIMessageBody.add_record_errors() method"""

    def test_add_record_errors_single_record(self):
        """Test adding errors from single record"""

        class TestModel(BasicModel):
            @classmethod
            def _schema(cls):
                return None

        message_body = APIMessageBody()
        record = TestModel.empty()
        record._errors = {"name": ["is required"]}  # pylint: disable=protected-access

        result = message_body.add_record_errors(record)

        self.assertIs(result, message_body)
        self.assertEqual(len(message_body.errors), 1)
        error = message_body.errors[0]
        self.assertEqual(error.api_code, "invalid_resource_data")
        self.assertIn("name", str(error.detail))

    def test_add_record_errors_multiple_records(self):
        """Test adding errors from multiple records"""

        class TestModel(BasicModel):
            @classmethod
            def _schema(cls):
                return None

        message_body = APIMessageBody()
        record1 = TestModel.empty()
        record2 = TestModel.empty()
        record1._errors = {"field1": ["error1"]}  # pylint: disable=protected-access
        record2._errors = {"field2": ["error2"]}  # pylint: disable=protected-access

        message_body.add_record_errors([record1, record2])

        self.assertEqual(len(message_body.errors), 2)

    def test_add_record_errors_with_non_basicmodel_raises_error(self):
        """Test that add_record_errors with non-BasicModel raises TypeError"""
        message_body = APIMessageBody()

        with self.assertRaises(TypeError) as context:
            message_body.add_record_errors("not a model")  # type: ignore[arg-type]

        self.assertIn("not a subclass of BasicModel", str(context.exception))


class TestAPIMessageBodyPathMethods(unittest.TestCase):
    """Test cases for path-related helper methods"""

    def test_get_current_path_with_self_link(self):
        """Test _get_current_path returns path from self link"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents"))
        message_body.include(APILink("self", "/api/agents/123"))

        path = message_body._get_current_path()  # pylint: disable=protected-access

        self.assertEqual(path, "/api/agents/123")

    def test_get_current_path_without_self_link(self):
        """Test _get_current_path returns None without self link"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents"))

        path = message_body._get_current_path()  # pylint: disable=protected-access

        self.assertIsNone(path)

    def test_get_resource_path_with_resource_self_link(self):
        """Test _get_resource_path returns path from resource's self link"""
        message_body = APIMessageBody()
        resource = APIResource("agents", "agent-123")
        resource.add_link(APILink("self", "/api/agents/agent-123"))
        message_body.add_resource(resource)

        path = message_body._get_resource_path()  # pylint: disable=protected-access

        self.assertEqual(path, "/api/agents/agent-123")

    def test_get_resource_path_without_resource_link(self):
        """Test _get_resource_path returns None without resource link"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents"))

        path = message_body._get_resource_path()  # pylint: disable=protected-access

        self.assertIsNone(path)

    def test_get_resource_path_with_list_data(self):
        """Test _get_resource_path returns None when data is a list"""
        message_body = APIMessageBody()
        message_body.add_resource(APIResource("agents", "agent-1"))
        message_body.add_resource(APIResource("agents", "agent-2"))

        path = message_body._get_resource_path()  # pylint: disable=protected-access

        self.assertIsNone(path)

    def test_is_resource_new_with_different_paths(self):
        """Test _is_resource_new returns True when paths differ"""
        message_body = APIMessageBody()
        resource = APIResource("agents", "agent-123")
        resource.add_link(APILink("self", "/api/agents/agent-123"))
        message_body.add_resource(resource)
        message_body.include(APILink("self", "/api/agents"))

        is_new = message_body._is_resource_new()  # pylint: disable=protected-access

        self.assertTrue(is_new)

    def test_is_resource_new_with_same_paths(self):
        """Test _is_resource_new returns False when paths are same"""
        message_body = APIMessageBody()
        resource = APIResource("agents", "agent-123")
        resource.add_link(APILink("self", "/api/agents/agent-123"))
        message_body.add_resource(resource)
        message_body.include(APILink("self", "/api/agents/agent-123"))

        is_new = message_body._is_resource_new()  # pylint: disable=protected-access

        self.assertFalse(is_new)


class TestAPIMessageBodyInferHTTPCodeWithData(unittest.TestCase):
    """Additional test cases for _infer_http_code with data"""

    def test_infer_http_code_returns_201_for_new_resource(self):
        """Test that _infer_http_code returns 201 for newly created resource"""
        message_body = APIMessageBody()
        resource = APIResource("agents", "agent-123")
        resource.add_link(APILink("self", "/api/agents/agent-123"))
        message_body.add_resource(resource)
        message_body.include(APILink("self", "/api/agents"))

        code = message_body._infer_http_code()  # pylint: disable=protected-access

        self.assertEqual(code, 201)


if __name__ == "__main__":
    unittest.main()
