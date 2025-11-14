"""
Unit tests for keylime.web.base.api_messages module
"""

import unittest

# Import directly from submodules to avoid circular import
from keylime.web.base.api_messages.api_error import APIError
from keylime.web.base.api_messages.api_info import APIInfo
from keylime.web.base.api_messages.api_links import APILink
from keylime.web.base.api_messages.api_message_body import APIMessageBody
from keylime.web.base.api_messages.api_meta import APIMeta
from keylime.web.base.api_messages.api_resource import APIResource


class TestAPIMessageBody(unittest.TestCase):
    """Test cases for APIMessageBody"""

    def test_api_message_body_initialization(self):
        """Test that APIMessageBody initializes correctly"""
        body = APIMessageBody()
        self.assertIsNotNone(body)

    def test_api_message_body_with_resource(self):
        """Test APIMessageBody with a resource"""
        resource = APIResource("agents", "test-123")
        body = APIMessageBody(resource)

        rendered = body.render()
        self.assertIn("data", rendered)

    def test_api_message_body_add_resource(self):
        """Test adding a resource to message body"""
        resource = APIResource("agents", "test-456")
        body = APIMessageBody()
        body.add_resource(resource)

        rendered = body.render()
        self.assertIn("data", rendered)


class TestAPIError(unittest.TestCase):
    """Test cases for APIError"""

    def test_api_error_initialization(self):
        """Test that APIError initializes correctly"""
        error = APIError("invalid_request")
        self.assertIsNotNone(error)

    def test_api_error_with_detail(self):
        """Test APIError with detail"""
        error = APIError("not_found", "Resource not found")
        rendered = error.render()
        self.assertIn("code", rendered)
        self.assertEqual(rendered["code"], "not_found")

    def test_api_error_with_http_code(self):
        """Test APIError with HTTP code and detail"""
        error = APIError("validation_error", 422, "Invalid input")
        rendered = error.render()
        self.assertIn("code", rendered)
        self.assertIn("status", rendered)
        self.assertEqual(rendered["status"], "422")


class TestAPIResource(unittest.TestCase):
    """Test cases for APIResource"""

    def test_api_resource_initialization(self):
        """Test that APIResource initializes correctly"""
        resource = APIResource("agents", "test-agent-123")
        self.assertIsNotNone(resource)
        self.assertEqual(resource.type, "agents")
        self.assertEqual(resource.id, "test-agent-123")

    def test_api_resource_render(self):
        """Test APIResource rendering"""
        resource = APIResource("agents", "test-123")
        rendered = resource.render()

        self.assertEqual(rendered["type"], "agents")
        self.assertEqual(rendered["id"], "test-123")


class TestAPILink(unittest.TestCase):
    """Test cases for APILink"""

    def test_api_link_initialization(self):
        """Test that APILink initializes correctly"""
        link = APILink("self", "/v3.0/agents")
        self.assertIsNotNone(link)

    def test_api_link_render(self):
        """Test APILink rendering"""
        link = APILink("related", "/v3.0/agents/123/relationships/office")
        rendered = link.render()
        self.assertIsInstance(rendered, str)


class TestAPIMeta(unittest.TestCase):
    """Test cases for APIMeta"""

    def test_api_meta_initialization(self):
        """Test that APIMeta initializes correctly"""
        meta = APIMeta("version", "3.0")
        self.assertIsNotNone(meta)

    def test_api_meta_render(self):
        """Test APIMeta rendering"""
        meta = APIMeta("timestamp", "2025-01-15T12:00:00Z")
        rendered = meta.render()
        self.assertIsInstance(rendered, str)


class TestAPIInfo(unittest.TestCase):
    """Test cases for APIInfo"""

    def test_api_info_initialization(self):
        """Test that APIInfo initializes correctly"""
        info = APIInfo()
        self.assertIsNotNone(info)

    def test_api_info_render(self):
        """Test APIInfo rendering"""
        info = APIInfo()
        rendered = info.render()
        self.assertIsInstance(rendered, dict)


class TestAPIMessageIntegration(unittest.TestCase):
    """Integration tests for API message components"""

    def test_complete_success_response(self):
        """Test building a complete success response"""
        # Create resource
        resource = APIResource("agents", "test-agent-123")

        # Create message body with resource
        body = APIMessageBody(resource)
        rendered = body.render()

        self.assertIn("data", rendered)
        self.assertEqual(rendered["data"]["type"], "agents")
        self.assertEqual(rendered["data"]["id"], "test-agent-123")

    def test_message_body_with_error(self):
        """Test building an error response"""
        error = APIError("not_found", 404, "Resource not found")

        body = APIMessageBody(error)
        rendered = body.render()

        self.assertIn("errors", rendered)


if __name__ == "__main__":
    unittest.main()
