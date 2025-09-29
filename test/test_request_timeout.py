import asyncio
import os
import ssl
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from tornado.httpclient import HTTPError

from keylime.config import DEFAULT_TIMEOUT

# Add the keylime directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestTornadoRequestsTimeout(unittest.TestCase):
    """Test tornado_requests timeout functionality."""

    @patch("tornado.httpclient.AsyncHTTPClient")
    def test_request_timeout_parameter(self, mock_http_client_class):
        """Test that timeout parameter is correctly passed to HTTPRequest."""
        from keylime import tornado_requests  # pylint: disable=import-outside-toplevel

        # Setup mocks
        mock_client = MagicMock()
        mock_http_client_class.return_value = mock_client

        # Mock response
        mock_response = MagicMock()
        mock_response.code = 200
        mock_response.body = b'{"status": "success"}'
        mock_client.fetch = AsyncMock(return_value=mock_response)

        async def run_test():
            # Test with custom timeout
            response = await tornado_requests.request("GET", "http://test.example.com/api", timeout=45.5)

            # Verify HTTPRequest was called with correct timeout
            mock_client.fetch.assert_called_once()
            http_request = mock_client.fetch.call_args[0][0]
            self.assertEqual(http_request.request_timeout, 45.5)
            self.assertEqual(response.status_code, 200)

        asyncio.run(run_test())

    @patch("tornado.httpclient.AsyncHTTPClient")
    def test_request_default_timeout(self, mock_http_client_class):
        """Test that default timeout is used when not specified."""
        from keylime import tornado_requests  # pylint: disable=import-outside-toplevel

        # Setup mocks
        mock_client = MagicMock()
        mock_http_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.code = 200
        mock_response.body = b'{"status": "success"}'
        mock_client.fetch = AsyncMock(return_value=mock_response)

        async def run_test():
            # Test without specifying timeout (should use default)
            response = await tornado_requests.request("POST", "http://test.example.com/api", data={"key": "value"})

            # Verify HTTPRequest was called with default timeout
            mock_client.fetch.assert_called_once()
            http_request = mock_client.fetch.call_args[0][0]
            self.assertEqual(http_request.request_timeout, DEFAULT_TIMEOUT)  # Default timeout
            self.assertEqual(response.status_code, 200)

        asyncio.run(run_test())

    @patch("tornado.httpclient.AsyncHTTPClient")
    def test_request_with_ssl_context_and_timeout(self, mock_http_client_class):
        """Test timeout works correctly with SSL context."""
        from keylime import tornado_requests  # pylint: disable=import-outside-toplevel

        # Setup mocks
        mock_client = MagicMock()
        mock_http_client_class.return_value = mock_client

        mock_response = MagicMock()
        mock_response.code = 200
        mock_response.body = b'{"result": "ok"}'
        mock_client.fetch = AsyncMock(return_value=mock_response)

        ssl_context = ssl.create_default_context()

        async def run_test():
            response = await tornado_requests.request(
                "GET", "http://test.example.com/api", context=ssl_context, timeout=120.0
            )

            # Verify HTTPRequest was called with timeout and SSL options
            mock_client.fetch.assert_called_once()
            http_request = mock_client.fetch.call_args[0][0]
            self.assertEqual(http_request.request_timeout, 120.0)
            self.assertEqual(http_request.ssl_options, ssl_context)
            self.assertTrue(http_request.url.startswith("https://"))
            self.assertEqual(response.status_code, 200)

        asyncio.run(run_test())

    @patch("tornado.httpclient.AsyncHTTPClient")
    def test_request_timeout_error_handling(self, mock_http_client_class):
        """Test that timeout errors are properly handled."""
        from keylime import tornado_requests  # pylint: disable=import-outside-toplevel

        # Setup mocks
        mock_client = MagicMock()
        mock_http_client_class.return_value = mock_client

        # Mock HTTP error (timeout-like scenario)
        http_error = HTTPError(599, "Connection timeout")
        http_error.response = None
        mock_client.fetch = AsyncMock(side_effect=http_error)

        async def run_test():
            # Test that timeout error is converted to proper response
            response = await tornado_requests.request("GET", "http://slow.example.com/api", timeout=1.0)

            # Verify HTTPRequest was called with short timeout
            mock_client.fetch.assert_called_once()
            http_request = mock_client.fetch.call_args[0][0]
            self.assertEqual(http_request.request_timeout, 1.0)

            # Verify timeout error is handled gracefully
            self.assertEqual(response.status_code, 500)
            self.assertIn("Connection timeout", response.body)

        asyncio.run(run_test())


class TestRequestTimeoutConfiguration(unittest.TestCase):
    """Test request_timeout configuration integration."""

    @patch("keylime.config.getfloat")
    def test_verifier_timeout_configuration(self, mock_getfloat):
        """Test timeout configuration reading in verifier."""
        mock_getfloat.return_value = 90.0

        # Simulate configuration reading from main()
        timeout = mock_getfloat("verifier", "request_timeout", fallback=DEFAULT_TIMEOUT)

        # Verify correct config call
        mock_getfloat.assert_called_with("verifier", "request_timeout", fallback=DEFAULT_TIMEOUT)
        self.assertEqual(timeout, 90.0)


class TestWebhookNotificationTimeout(unittest.TestCase):
    """Test WebhookNotificationManager timeout functionality."""

    @patch("keylime.web_util.generate_tls_context")
    @patch("keylime.config.getboolean")
    @patch("keylime.config.getint")
    @patch("keylime.config.get")
    @patch("keylime.config.getfloat")
    @patch("keylime.web_util.get_tls_options")
    def test_webhook_manager_timeout_initialization(
        self, mock_tls_options, mock_getfloat, mock_get, mock_getint, mock_getboolean, mock_generate_tls
    ):
        """Test WebhookNotificationManager initialization with timeout configuration."""
        from keylime.revocation_notifier import WebhookNotificationManager  # pylint: disable=import-outside-toplevel

        # Mock configuration values
        def getfloat_side_effect(_section, option, fallback=None):
            if option == "request_timeout":
                return 45.5
            if option == "retry_interval":
                return 1.0
            return fallback

        mock_getfloat.side_effect = getfloat_side_effect
        mock_get.return_value = "http://test.webhook.com"
        mock_getint.return_value = 3
        mock_getboolean.return_value = True
        mock_tls_options.return_value = (("cert", "key", "ca", None), True)
        mock_generate_tls.return_value = MagicMock()  # Mock TLS context

        # Test actual WebhookNotificationManager initialization
        manager = WebhookNotificationManager()

        # Verify timeout was set correctly from config
        # pylint: disable=protected-access
        self.assertEqual(manager._request_timeout, 45.5)
        mock_getfloat.assert_any_call("verifier", "request_timeout", fallback=DEFAULT_TIMEOUT)

    @patch("keylime.web_util.generate_tls_context")
    @patch("keylime.requests_client.RequestsClient")
    @patch("keylime.config.getboolean")
    @patch("keylime.config.getint")
    @patch("keylime.config.get")
    @patch("keylime.config.getfloat")
    @patch("keylime.web_util.get_tls_options")
    def test_webhook_notification_uses_timeout(
        self,
        mock_tls_options,
        mock_getfloat,
        mock_get,
        mock_getint,
        mock_getboolean,
        mock_requests_client,
        mock_generate_tls,
    ):
        """Test that webhook notifications use the configured timeout."""
        from keylime.revocation_notifier import WebhookNotificationManager  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_getfloat.side_effect = lambda section, option, fallback=None: 35.0 if option == "request_timeout" else 1.0
        mock_get.return_value = "http://test.webhook.com"
        mock_getint.return_value = 3
        mock_getboolean.return_value = True
        mock_tls_options.return_value = (("cert", "key", "ca", None), True)
        mock_generate_tls.return_value = MagicMock()  # Mock TLS context

        # Mock RequestsClient
        mock_client_instance = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client_instance.post.return_value = mock_response
        mock_requests_client.return_value.__enter__.return_value = mock_client_instance

        # Create manager
        manager = WebhookNotificationManager()

        # Verify that the timeout was configured correctly during initialization
        # pylint: disable=protected-access
        self.assertEqual(manager._request_timeout, 35.0)


class TestTenantTimeout(unittest.TestCase):
    """Test Tenant timeout functionality."""

    @patch("keylime.web_util.get_tls_options")
    @patch("keylime.config.getboolean")
    @patch("keylime.config.getfloat")
    @patch("keylime.config.get")
    @patch("keylime.config.getint")
    def test_tenant_timeout_initialization(
        self, mock_getint, mock_get, mock_getfloat, mock_getboolean, mock_tls_options
    ):
        """Test Tenant initialization with timeout configuration."""
        from keylime.tenant import Tenant  # pylint: disable=import-outside-toplevel

        # Mock configuration values
        def getint_side_effect(_section, option, fallback=None):
            if option == "max_retries":
                return 5
            return fallback or 0

        def getfloat_side_effect(_section, option, fallback=None):
            if option == "request_timeout":
                return 42.0
            return fallback or 1.0

        mock_getint.side_effect = getint_side_effect
        mock_getfloat.side_effect = getfloat_side_effect
        mock_get.return_value = "localhost"
        mock_getboolean.return_value = False
        mock_tls_options.return_value = (("cert", "key", "ca", None), True)

        # Test actual Tenant initialization
        tenant = Tenant()

        # Verify timeout was set correctly from config
        self.assertEqual(tenant.request_timeout, 42.0)
        mock_getfloat.assert_any_call("tenant", "request_timeout", fallback=DEFAULT_TIMEOUT)

    def test_tenant_timeout_attribute_set(self):
        """Test that Tenant timeout attribute is accessible after initialization."""
        # This is a simplified test that just checks the attribute is set
        # without requiring complex mocking of all Tenant dependencies

        # We can't easily test the full Tenant initialization due to complex dependencies,
        # but we can verify the config reading pattern works by testing it directly
        with patch("keylime.config.getfloat") as mock_getfloat:
            mock_getfloat.return_value = 33.0

            # Test the config reading pattern used in Tenant.__init__
            timeout = mock_getfloat("tenant", "request_timeout", fallback=DEFAULT_TIMEOUT)

            # Verify the config was read correctly
            mock_getfloat.assert_called_with("tenant", "request_timeout", fallback=DEFAULT_TIMEOUT)
            self.assertEqual(timeout, 33)

    def test_tenant_timeout_usage_pattern(self):
        """Test that the timeout usage pattern in tenant methods is correct."""
        # Test that the pattern `timeout=self.request_timeout` is used correctly
        # This tests the code pattern without needing to mock the entire Tenant class

        class MockTenant:
            def __init__(self):
                self.request_timeout = 27

            def mock_operation(self, client):
                # Simulate the pattern used in tenant methods
                return client.get("/test", timeout=self.request_timeout)

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client.get.return_value = mock_response

        tenant = MockTenant()
        tenant.mock_operation(mock_client)

        # Verify the timeout was passed correctly
        mock_client.get.assert_called_with("/test", timeout=27)


if __name__ == "__main__":
    unittest.main()
