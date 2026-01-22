"""Integration tests for the authorization framework.

Tests cover:
- Identity extraction from bearer tokens and mTLS certificates
- Authorization flow through ActionHandler
- Security model enforcement (authentication method separation)
- End-to-end authorization checks
"""

import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch

import keylime.authorization.manager as manager_module
from keylime.authorization.manager import AuthorizationManager
from keylime.authorization.provider import Action, AuthorizationRequest, AuthorizationResponse
from keylime.models.base.types import Timestamp
from keylime.shared_data import cleanup_global_shared_memory, get_shared_memory
from keylime.web.base.action_handler import ActionHandler


class TestIdentityExtraction(unittest.TestCase):
    """Test _extract_identity() in ActionHandler."""

    def setUp(self):
        """Set up test fixtures."""
        cleanup_global_shared_memory()
        self.shared_memory = get_shared_memory()
        self.sessions_cache = self.shared_memory.get_or_create_dict("auth_sessions")

    def tearDown(self):
        """Clean up after tests."""
        cleanup_global_shared_memory()

    def _create_handler_with_auth_header(self, auth_header: str | None) -> ActionHandler:
        """Create a mock ActionHandler with specified Authorization header."""
        handler = ActionHandler.__new__(ActionHandler)
        handler.request = MagicMock()
        handler.request.headers = MagicMock()
        handler.request.headers.get = MagicMock(side_effect=lambda h: auth_header if h == "Authorization" else None)
        handler.request.get_ssl_certificate = MagicMock(return_value=None)
        return handler

    def _create_handler_with_mtls_cert(self, common_name: str) -> ActionHandler:
        """Create a mock ActionHandler with mTLS certificate."""
        handler = ActionHandler.__new__(ActionHandler)
        handler.request = MagicMock()
        handler.request.headers = MagicMock()
        handler.request.headers.get = MagicMock(return_value=None)  # No Authorization header

        # Mock SSL certificate with CN
        cert_dict = {"subject": ((("commonName", common_name),),)}
        handler.request.get_ssl_certificate = MagicMock(return_value=cert_dict)
        return handler

    def test_agent_identity_from_valid_bearer_token(self):
        """Test that valid bearer token returns agent identity."""
        agent_id = "test-agent-123"

        # Create handler with bearer token
        handler = self._create_handler_with_auth_header("Bearer valid-token")

        # Mock AuthSession.get with valid unexpired token
        mock_session = MagicMock()
        mock_session.agent_id = agent_id
        # Use Timestamp.now() + timedelta to create future expiry
        future_time = Timestamp.now() + timedelta(hours=1)
        mock_session.token_expires_at = future_time

        with patch("keylime.web.base.action_handler.AuthSession.get", return_value=mock_session):
            identity, identity_type = handler._extract_identity()  # pylint: disable=protected-access

        self.assertEqual(identity, agent_id)
        self.assertEqual(identity_type, "agent")

    def test_anonymous_for_expired_bearer_token(self):
        """Test that expired bearer token returns anonymous identity."""
        agent_id = "test-agent-123"

        # Create handler with bearer token
        handler = self._create_handler_with_auth_header("Bearer expired-token")

        # Mock AuthSession.get with expired token
        mock_session = MagicMock()
        mock_session.agent_id = agent_id
        # Use Timestamp.now() - timedelta to create past expiry
        past_time = Timestamp.now() - timedelta(hours=1)
        mock_session.token_expires_at = past_time  # Expired

        with patch("keylime.web.base.action_handler.AuthSession.get", return_value=mock_session):
            identity, identity_type = handler._extract_identity()  # pylint: disable=protected-access

        self.assertEqual(identity, "anonymous")
        self.assertEqual(identity_type, "anonymous")

    def test_anonymous_for_invalid_bearer_token(self):
        """Test that invalid bearer token returns anonymous identity."""
        # Create handler with bearer token
        handler = self._create_handler_with_auth_header("Bearer invalid-token")

        # Mock AuthSession.get returning None (not found)
        with patch("keylime.web.base.action_handler.AuthSession.get", return_value=None):
            identity, identity_type = handler._extract_identity()  # pylint: disable=protected-access

        self.assertEqual(identity, "anonymous")
        self.assertEqual(identity_type, "anonymous")

    def test_no_mtls_fallback_when_bearer_token_invalid(self):
        """Test that invalid bearer token does NOT fall back to mTLS.

        This is a critical security test - if an attacker has both a valid
        mTLS certificate AND sends an invalid bearer token, they should NOT
        be authenticated as admin.
        """
        handler = ActionHandler.__new__(ActionHandler)
        handler.request = MagicMock()

        # Set up headers with invalid bearer token
        handler.request.headers = MagicMock()
        handler.request.headers.get = MagicMock(return_value="Bearer invalid-token")

        # Set up valid mTLS certificate (this should be ignored!)
        cert_dict = {"subject": ((("commonName", "admin-cn"),),)}
        handler.request.get_ssl_certificate = MagicMock(return_value=cert_dict)

        # Mock AuthSession.get returning None (invalid token)
        with patch("keylime.web.base.action_handler.AuthSession.get", return_value=None):
            identity, identity_type = handler._extract_identity()  # pylint: disable=protected-access

        # Should be anonymous, NOT admin (mTLS should not be checked)
        self.assertEqual(identity, "anonymous")
        self.assertEqual(identity_type, "anonymous")

    def test_admin_identity_from_mtls_certificate(self):
        """Test that mTLS certificate returns admin identity."""
        handler = self._create_handler_with_mtls_cert("admin-cn")

        identity, identity_type = handler._extract_identity()  # pylint: disable=protected-access

        self.assertEqual(identity, "admin-cn")
        self.assertEqual(identity_type, "admin")

    def test_anonymous_for_no_authentication(self):
        """Test that no auth header and no certificate returns anonymous."""
        handler = self._create_handler_with_auth_header(None)

        identity, identity_type = handler._extract_identity()  # pylint: disable=protected-access

        self.assertEqual(identity, "anonymous")
        self.assertEqual(identity_type, "anonymous")

    def test_malformed_auth_header_returns_anonymous(self):
        """Test that malformed Authorization header returns anonymous."""
        # Missing Bearer prefix
        handler = self._create_handler_with_auth_header("token-without-bearer")

        identity, identity_type = handler._extract_identity()  # pylint: disable=protected-access

        self.assertEqual(identity, "anonymous")
        self.assertEqual(identity_type, "anonymous")

    def test_basic_auth_header_returns_anonymous(self):
        """Test that Basic auth (not Bearer) returns anonymous."""
        handler = self._create_handler_with_auth_header("Basic dXNlcjpwYXNz")

        identity, identity_type = handler._extract_identity()  # pylint: disable=protected-access

        self.assertEqual(identity, "anonymous")
        self.assertEqual(identity_type, "anonymous")

    def test_extract_san_from_cert_with_all_types(self):
        """Test SAN extraction includes email, DNS, URI, and IP Address."""
        handler = ActionHandler.__new__(ActionHandler)

        cert_dict = {
            "subjectAltName": (
                ("email", "admin@example.com"),
                ("DNS", "admin.example.com"),
                ("URI", "spiffe://example.com/admin"),
                ("IP Address", "192.168.1.1"),
                ("dirName", "CN=test"),  # Should be excluded
            )
        }

        san_info = handler._extract_san_from_cert(cert_dict)  # pylint: disable=protected-access

        self.assertIn("email=admin@example.com", san_info)
        self.assertIn("DNS=admin.example.com", san_info)
        self.assertIn("URI=spiffe://example.com/admin", san_info)
        self.assertIn("IP Address=192.168.1.1", san_info)
        self.assertNotIn("dirName", san_info)

    def test_extract_san_from_cert_empty(self):
        """Test SAN extraction with no SAN entries."""
        handler = ActionHandler.__new__(ActionHandler)

        cert_dict = {}

        san_info = handler._extract_san_from_cert(cert_dict)  # pylint: disable=protected-access

        self.assertEqual(san_info, "")

    def test_extract_san_from_cert_only_excluded_types(self):
        """Test SAN extraction with only excluded types returns empty."""
        handler = ActionHandler.__new__(ActionHandler)

        cert_dict = {
            "subjectAltName": (
                ("dirName", "CN=test"),
                ("otherName", "1.2.3.4"),
            )
        }

        san_info = handler._extract_san_from_cert(cert_dict)  # pylint: disable=protected-access

        self.assertEqual(san_info, "")


class TestAuthorizationCheckFlow(unittest.TestCase):
    """Test _check_authorization() flow in ActionHandler."""

    def setUp(self):
        """Set up test fixtures."""
        cleanup_global_shared_memory()

    def tearDown(self):
        """Clean up after tests."""
        cleanup_global_shared_memory()

    def _create_handler_with_route(
        self,
        auth_header: str | None = None,
        mtls_cn: str | None = None,
        requires_auth: bool = True,
        route_method: str = "GET",
        route_pattern: str = "/agents",
        auth_action: Action | None = None,
    ) -> ActionHandler:
        """Create a mock ActionHandler with specified route and auth."""
        handler = ActionHandler.__new__(ActionHandler)
        handler.request = MagicMock()

        # Set up headers
        handler.request.headers = MagicMock()
        handler.request.headers.get = MagicMock(side_effect=lambda h: auth_header if h == "Authorization" else None)
        handler.request.method = route_method
        handler.request.path = route_pattern

        # Set up mTLS certificate
        if mtls_cn:
            cert_dict = {"subject": ((("commonName", mtls_cn),),)}
            handler.request.get_ssl_certificate = MagicMock(return_value=cert_dict)
        else:
            handler.request.get_ssl_certificate = MagicMock(return_value=None)

        # Set up matching route (use _matching_route, the private attribute)
        mock_route = MagicMock()
        mock_route.requires_auth = requires_auth
        mock_route.method = route_method.lower()
        mock_route.pattern = route_pattern
        mock_route.capture_params = MagicMock(return_value={})
        mock_route.auth_action = auth_action
        handler._matching_route = mock_route  # pylint: disable=protected-access

        # Set up mock server with component
        mock_server = MagicMock()
        mock_server.component = "verifier"
        handler._server = mock_server  # pylint: disable=protected-access

        # Set up response methods
        handler.set_status = MagicMock()
        handler.write = MagicMock()
        handler.finish = MagicMock()

        return handler

    def test_skip_auth_for_public_route(self):
        """Test that routes not requiring auth skip authorization check."""
        handler = self._create_handler_with_route(requires_auth=False)

        result = handler._check_authorization()  # pylint: disable=protected-access

        self.assertTrue(result)
        handler.set_status.assert_not_called()  # type: ignore[union-attr]  # No error response

    @patch("keylime.web.base.action_handler.get_authorization_manager")
    def test_admin_can_access_admin_route(self, mock_get_manager):
        """Test that admin with mTLS can access admin routes."""
        handler = self._create_handler_with_route(
            mtls_cn="admin-user", route_method="GET", route_pattern="/agents", auth_action=Action.LIST_AGENTS
        )

        # Mock authorization manager to return allowed
        mock_manager = MagicMock()
        mock_manager.authorize.return_value = AuthorizationResponse(allowed=True, reason="Admin authorized")
        mock_get_manager.return_value = mock_manager

        result = handler._check_authorization()  # pylint: disable=protected-access

        self.assertTrue(result)
        handler.set_status.assert_not_called()  # type: ignore[union-attr]

    @patch("keylime.web.base.action_handler.get_authorization_manager")
    def test_anonymous_denied_for_admin_route(self, mock_get_manager):
        """Test that anonymous user is denied for admin routes."""
        handler = self._create_handler_with_route(
            route_method="DELETE", route_pattern="/agents/:agent_id", auth_action=Action.DELETE_AGENT
        )

        # Mock authorization manager to return denied
        mock_manager = MagicMock()
        mock_manager.authorize.return_value = AuthorizationResponse(
            allowed=False, reason="Admin actions require mTLS certificate authentication"
        )
        mock_get_manager.return_value = mock_manager

        result = handler._check_authorization()  # pylint: disable=protected-access

        self.assertFalse(result)
        handler.set_status.assert_called_with(403)  # type: ignore[union-attr]
        handler.finish.assert_called()  # type: ignore[union-attr]

    @patch("keylime.web.base.action_handler.AuthSession.get")
    @patch("keylime.web.base.action_handler.get_authorization_manager")
    def test_agent_can_access_own_resource(self, mock_get_manager, mock_auth_session_get):
        """Test that agent can access their own resource."""
        agent_id = "agent-123"

        handler = self._create_handler_with_route(
            auth_header="Bearer valid-token",
            route_method="POST",
            route_pattern="/agents/:agent_id/attestations",
            auth_action=Action.SUBMIT_ATTESTATION,
        )
        handler._matching_route.capture_params.return_value = {"agent_id": agent_id}  # type: ignore[union-attr]  # pylint: disable=protected-access

        # Mock valid agent session
        mock_session = MagicMock()
        mock_session.agent_id = agent_id
        future_time = Timestamp.now() + timedelta(hours=1)
        mock_session.token_expires_at = future_time
        mock_auth_session_get.return_value = mock_session

        # Mock authorization manager to return allowed
        mock_manager = MagicMock()
        mock_manager.authorize.return_value = AuthorizationResponse(
            allowed=True, reason=f"Agent {agent_id} accessing own resource"
        )
        mock_get_manager.return_value = mock_manager

        result = handler._check_authorization()  # pylint: disable=protected-access

        self.assertTrue(result)
        handler.set_status.assert_not_called()  # type: ignore[union-attr]

    @patch("keylime.web.base.action_handler.AuthSession.get")
    @patch("keylime.web.base.action_handler.get_authorization_manager")
    def test_agent_cannot_access_other_agent_resource(self, mock_get_manager, mock_auth_session_get):
        """Test that agent cannot access another agent's resource."""
        own_agent_id = "agent-123"
        other_agent_id = "agent-456"

        handler = self._create_handler_with_route(
            auth_header="Bearer valid-token",
            route_method="POST",
            route_pattern="/agents/:agent_id/attestations",
            auth_action=Action.SUBMIT_ATTESTATION,
        )
        handler._matching_route.capture_params.return_value = {  # type: ignore[union-attr]  # pylint: disable=protected-access
            "agent_id": other_agent_id
        }

        # Mock valid agent session
        mock_session = MagicMock()
        mock_session.agent_id = own_agent_id
        future_time = Timestamp.now() + timedelta(hours=1)
        mock_session.token_expires_at = future_time
        mock_auth_session_get.return_value = mock_session

        # Mock authorization manager to return denied
        mock_manager = MagicMock()
        mock_manager.authorize.return_value = AuthorizationResponse(
            allowed=False, reason=f"Agent {own_agent_id} cannot access resource {other_agent_id} (ownership required)"
        )
        mock_get_manager.return_value = mock_manager

        result = handler._check_authorization()  # pylint: disable=protected-access

        self.assertFalse(result)
        handler.set_status.assert_called_with(403)  # type: ignore[union-attr]


class TestSecurityModelIntegration(unittest.TestCase):
    """Integration tests for the complete security model."""

    def setUp(self):
        """Set up test fixtures."""
        cleanup_global_shared_memory()

        # Create real authorization manager with simple provider
        manager_module._manager = None  # pylint: disable=protected-access  # Reset global manager
        self.auth_manager = AuthorizationManager()

    def tearDown(self):
        """Clean up after tests."""
        cleanup_global_shared_memory()

    def test_public_action_allowed_for_all_identity_types(self):
        """Test that public actions are allowed for any identity type."""
        identity_types = [
            ("anonymous", "anonymous"),
            ("agent-123", "agent"),
            ("admin-cn", "admin"),
        ]

        for identity, identity_type in identity_types:
            request = AuthorizationRequest(
                identity=identity,
                identity_type=identity_type,
                action=Action.READ_VERSION,
                resource=None,
            )
            response = self.auth_manager.authorize(request)

            self.assertTrue(
                response.allowed,
                f"Public action should be allowed for {identity_type}, but got: {response.reason}",
            )

    def test_agent_action_requires_agent_identity_type(self):
        """Test that agent actions require agent identity_type."""
        # Agent with correct identity_type
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-123",
        )
        response = self.auth_manager.authorize(request)
        self.assertTrue(response.allowed)

        # Admin trying to use agent action - should be denied
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-123",
        )
        response = self.auth_manager.authorize(request)
        self.assertFalse(response.allowed)

    def test_agent_action_requires_resource_ownership(self):
        """Test that agent actions require identity == resource."""
        # Agent accessing own resource
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-123",
        )
        response = self.auth_manager.authorize(request)
        self.assertTrue(response.allowed)

        # Agent accessing other agent's resource
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-456",
        )
        response = self.auth_manager.authorize(request)
        self.assertFalse(response.allowed)

    def test_admin_action_requires_admin_identity_type(self):
        """Test that admin actions require admin identity_type."""
        # Admin with correct identity_type
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.CREATE_AGENT,
            resource=None,
        )
        response = self.auth_manager.authorize(request)
        self.assertTrue(response.allowed)

        # Agent trying to use admin action - should be denied
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.CREATE_AGENT,
            resource=None,
        )
        response = self.auth_manager.authorize(request)
        self.assertFalse(response.allowed)

    def test_strict_role_separation_admin_cannot_use_agent_only_actions(self):
        """Test that admins cannot use agent-only actions.

        This ensures strict separation - admins cannot submit attestations,
        which are reserved for agents only.
        """
        agent_only_actions = [
            Action.SUBMIT_ATTESTATION,
        ]

        for action in agent_only_actions:
            request = AuthorizationRequest(
                identity="admin-cn",
                identity_type="admin",
                action=action,
                resource="admin-cn",  # Even if identity == resource
            )
            response = self.auth_manager.authorize(request)

            self.assertFalse(
                response.allowed,
                f"Admin should NOT be allowed to access agent-only action {action.value}",
            )

    def test_admin_can_access_agent_or_admin_actions(self):
        """Test that admins can access actions shared with agents.

        Actions like READ_AGENT should be accessible to both agents (for their own
        resources) and admins (for any resource).
        """
        agent_or_admin_actions = [
            Action.READ_AGENT,
        ]

        for action in agent_or_admin_actions:
            request = AuthorizationRequest(
                identity="admin-cn",
                identity_type="admin",
                action=action,
                resource="any-agent-id",  # Admin can access any agent
            )
            response = self.auth_manager.authorize(request)

            self.assertTrue(
                response.allowed,
                f"Admin should be allowed to access agent-or-admin action {action.value}",
            )

    def test_fail_safe_on_authorization_error(self):
        """Test that authorization errors result in deny (fail-safe)."""
        # Create manager with mocked provider that raises exception
        mock_provider = MagicMock()
        mock_provider.authorize.side_effect = Exception("Test error")
        mock_provider.get_name.return_value = "mock"

        manager = AuthorizationManager()
        manager._provider = mock_provider  # pylint: disable=protected-access

        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.CREATE_AGENT,
            resource=None,
        )
        response = manager.authorize(request)

        # Should deny on error (fail-safe)
        self.assertFalse(response.allowed)
        self.assertIn("error", response.reason.lower())


if __name__ == "__main__":
    unittest.main()
