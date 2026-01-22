"""Unit tests for the authorization framework.

Tests cover:
- SimpleAuthProvider authorization logic
- Action enum and categorization
- AuthorizationManager provider loading
- Identity extraction and authentication separation
"""

import unittest
from unittest.mock import MagicMock

import keylime.authorization.manager as manager_module
from keylime.authorization.manager import AuthorizationManager
from keylime.authorization.provider import Action, AuthorizationRequest
from keylime.authorization.providers.simple import SimpleAuthProvider
from keylime.web.base.controller import Controller
from keylime.web.base.route import Route


class TestSimpleAuthProvider(unittest.TestCase):
    """Test SimpleAuthProvider authorization logic."""

    def setUp(self):
        """Create a SimpleAuthProvider instance for testing."""
        self.provider = SimpleAuthProvider({})

    def test_provider_name(self):
        """Test provider returns correct name."""
        self.assertEqual(self.provider.get_name(), "simple")

    def test_health_check(self):
        """Test provider health check returns True."""
        self.assertTrue(self.provider.health_check())

    # PUBLIC actions tests

    def test_public_action_read_version_anonymous(self):
        """Test anonymous user can read version (public action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.READ_VERSION,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_public_action_read_server_info_anonymous(self):
        """Test anonymous user can read server info (public action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.READ_SERVER_INFO,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_public_action_create_session_anonymous(self):
        """Test anonymous user can create session (public action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.CREATE_SESSION,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_public_action_verify_identity_anonymous(self):
        """Test anonymous user can verify identity (public action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.VERIFY_IDENTITY,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_public_action_verify_evidence_anonymous(self):
        """Test anonymous user can verify evidence (public action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.VERIFY_EVIDENCE,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_public_action_allowed_for_agent(self):
        """Test agent can access public actions."""
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.READ_VERSION,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_public_action_allowed_for_admin(self):
        """Test admin can access public actions."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.READ_VERSION,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    # Registrar PUBLIC actions tests

    def test_public_action_register_agent_anonymous(self):
        """Test anonymous can register agent (registrar public action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.REGISTER_AGENT,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_public_action_activate_agent_anonymous(self):
        """Test anonymous can activate agent (registrar public action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.ACTIVATE_AGENT,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    # Registrar ADMIN actions tests

    def test_admin_action_list_registrations(self):
        """Test admin can list registrations."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.LIST_REGISTRATIONS,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_admin_action_read_registration(self):
        """Test admin can read registration."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.READ_REGISTRATION,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_admin_action_delete_registration(self):
        """Test admin can delete registration."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.DELETE_REGISTRATION,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_anonymous_cannot_list_registrations(self):
        """Test anonymous cannot list registrations (admin action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.LIST_REGISTRATIONS,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)

    def test_anonymous_cannot_delete_registration(self):
        """Test anonymous cannot delete registration (admin action)."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.DELETE_REGISTRATION,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)

    # AGENT actions tests

    def test_agent_action_submit_attestation_own_resource(self):
        """Test agent can submit attestation for own resource."""
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_agent_action_submit_attestation_other_resource_denied(self):
        """Test agent cannot submit attestation for other agent's resource."""
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-456",
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)

    def test_agent_action_read_agent_own_resource(self):
        """Test agent can read own status."""
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.READ_AGENT,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_agent_action_read_agent_other_resource_denied(self):
        """Test agent cannot read other agent's status."""
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.READ_AGENT,
            resource="agent-456",
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)

    def test_public_action_extend_session(self):
        """Test extend session is public (session controller validates PoP/token internally)."""
        # Anonymous can trigger extend session - the session controller validates internally
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.EXTEND_SESSION,
            resource="session-123",
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_agent_action_denied_for_admin(self):
        """Test admin cannot access agent actions (strict separation)."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)

    def test_agent_action_denied_for_anonymous(self):
        """Test anonymous cannot access agent actions."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)

    # ADMIN actions tests

    def test_admin_action_create_agent(self):
        """Test admin can create agent."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.CREATE_AGENT,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_admin_action_delete_agent(self):
        """Test admin can delete agent."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.DELETE_AGENT,
            resource="agent-123",
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_admin_action_list_agents(self):
        """Test admin can list agents."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.LIST_AGENTS,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_admin_action_create_runtime_policy(self):
        """Test admin can create runtime policy."""
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.CREATE_RUNTIME_POLICY,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertTrue(response.allowed)

    def test_admin_action_denied_for_agent(self):
        """Test agent cannot access admin actions."""
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.CREATE_AGENT,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)

    def test_admin_action_denied_for_anonymous(self):
        """Test anonymous cannot access admin actions."""
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.CREATE_AGENT,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)


class TestAuthorizationCategories(unittest.TestCase):
    """Test that actions are correctly categorized."""

    def setUp(self):
        """Create a SimpleAuthProvider instance for testing."""
        self.provider = SimpleAuthProvider({})

    def test_public_actions_set(self):
        """Verify PUBLIC_ACTIONS contains expected actions."""
        expected_public = {
            # Verifier public actions
            Action.READ_VERSION,
            Action.READ_SERVER_INFO,
            Action.VERIFY_IDENTITY,
            Action.VERIFY_EVIDENCE,
            Action.CREATE_SESSION,
            Action.EXTEND_SESSION,  # Session controller validates PoP/token internally
            # Registrar public actions (agent self-registration)
            Action.REGISTER_AGENT,
            Action.ACTIVATE_AGENT,
        }
        self.assertEqual(self.provider.PUBLIC_ACTIONS, expected_public)

    def test_agent_only_actions_set(self):
        """Verify AGENT_ONLY_ACTIONS contains expected actions."""
        expected_agent_only = {
            Action.SUBMIT_ATTESTATION,
        }
        self.assertEqual(self.provider.AGENT_ONLY_ACTIONS, expected_agent_only)

    def test_agent_or_admin_actions_set(self):
        """Verify AGENT_OR_ADMIN_ACTIONS contains expected actions."""
        expected_agent_or_admin = {
            Action.READ_AGENT,
        }
        self.assertEqual(self.provider.AGENT_OR_ADMIN_ACTIONS, expected_agent_or_admin)

    def test_admin_actions_are_remainder(self):
        """Verify admin actions are all actions not in PUBLIC, AGENT_ONLY, or AGENT_OR_ADMIN."""
        all_actions = set(Action)
        non_admin = (
            self.provider.PUBLIC_ACTIONS | self.provider.AGENT_ONLY_ACTIONS | self.provider.AGENT_OR_ADMIN_ACTIONS
        )
        admin_actions = all_actions - non_admin

        # Verify some expected admin actions (verifier)
        self.assertIn(Action.CREATE_AGENT, admin_actions)
        self.assertIn(Action.DELETE_AGENT, admin_actions)
        self.assertIn(Action.LIST_AGENTS, admin_actions)
        self.assertIn(Action.CREATE_RUNTIME_POLICY, admin_actions)
        self.assertIn(Action.CREATE_MB_POLICY, admin_actions)
        # Verify registrar admin actions
        self.assertIn(Action.LIST_REGISTRATIONS, admin_actions)
        self.assertIn(Action.READ_REGISTRATION, admin_actions)
        self.assertIn(Action.DELETE_REGISTRATION, admin_actions)


class TestAuthorizationSecurityModel(unittest.TestCase):
    """Test security model enforcement."""

    def setUp(self):
        """Create a SimpleAuthProvider instance for testing."""
        self.provider = SimpleAuthProvider({})

    def test_admin_cannot_access_agent_only_endpoints(self):
        """Test that admin identity_type cannot access agent-only actions.

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
                resource="agent-123",
            )
            response = self.provider.authorize(request)
            self.assertFalse(
                response.allowed,
                f"Admin should NOT be allowed to access agent-only action {action.value}",
            )

    def test_admin_can_access_agent_or_admin_endpoints(self):
        """Test that admin identity_type can access agent-or-admin actions.

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
                resource="agent-123",
            )
            response = self.provider.authorize(request)
            self.assertTrue(
                response.allowed,
                f"Admin should be allowed to access agent-or-admin action {action.value}",
            )

    def test_agent_cannot_access_admin_endpoints(self):
        """Test that agent identity_type cannot access admin actions.

        This ensures agents with PoP tokens cannot perform admin operations.
        """
        admin_actions = [
            # Verifier admin actions
            Action.CREATE_AGENT,
            Action.DELETE_AGENT,
            Action.UPDATE_AGENT,
            Action.LIST_AGENTS,
            Action.CREATE_RUNTIME_POLICY,
            Action.DELETE_RUNTIME_POLICY,
            # Registrar admin actions
            Action.LIST_REGISTRATIONS,
            Action.READ_REGISTRATION,
            Action.DELETE_REGISTRATION,
        ]
        for action in admin_actions:
            request = AuthorizationRequest(
                identity="agent-123",
                identity_type="agent",
                action=action,
                resource=None,
            )
            response = self.provider.authorize(request)
            self.assertFalse(
                response.allowed,
                f"Agent should NOT be allowed to access admin action {action.value}",
            )

    def test_expired_token_becomes_anonymous_denied(self):
        """Test that expired token (anonymous) cannot access protected endpoints.

        When a bearer token is invalid/expired, the identity_type becomes
        "anonymous" and should be denied for non-public actions.
        """
        request = AuthorizationRequest(
            identity="anonymous",
            identity_type="anonymous",
            action=Action.CREATE_AGENT,
            resource=None,
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)

    def test_resource_ownership_required_for_agent(self):
        """Test that agents can only access their own resources."""
        request = AuthorizationRequest(
            identity="agent-123",
            identity_type="agent",
            action=Action.SUBMIT_ATTESTATION,
            resource="agent-456",  # Different from identity
        )
        response = self.provider.authorize(request)
        self.assertFalse(response.allowed)
        self.assertIn("ownership", response.reason.lower())


class TestAuthorizationManager(unittest.TestCase):
    """Test AuthorizationManager functionality."""

    def test_manager_loads_simple_provider_by_default(self):
        """Test that manager loads simple provider by default."""
        # Reset the global manager
        manager_module._manager = None  # pylint: disable=protected-access

        manager = AuthorizationManager()
        self.assertEqual(manager.get_provider_name(), "simple")

    def test_manager_authorize_logs_and_returns_response(self):
        """Test that manager correctly routes authorization requests."""
        manager = AuthorizationManager()
        request = AuthorizationRequest(
            identity="admin-cn",
            identity_type="admin",
            action=Action.CREATE_AGENT,
            resource=None,
        )
        response = manager.authorize(request)
        self.assertTrue(response.allowed)

    def test_manager_denies_on_provider_error(self):
        """Test that manager denies access if provider raises exception."""
        manager = AuthorizationManager()

        # Mock the provider to raise an exception
        assert manager._provider is not None  # pylint: disable=protected-access
        original_authorize = manager._provider.authorize  # pylint: disable=protected-access
        manager._provider.authorize = MagicMock(side_effect=Exception("Test error"))  # type: ignore[assignment]  # pylint: disable=protected-access

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

        # Restore original
        manager._provider.authorize = original_authorize  # type: ignore[assignment]  # pylint: disable=protected-access


class TestRouteAuthAction(unittest.TestCase):
    """Test that Route class correctly stores and returns auth_action metadata."""

    def test_route_stores_auth_action(self):
        """Test that Route correctly stores auth_action parameter."""
        class TestController(Controller):
            def index(self):
                pass

        route = Route("get", "/agents", TestController, "index", auth_action=Action.LIST_AGENTS)
        self.assertEqual(route.auth_action, Action.LIST_AGENTS)

    def test_route_auth_action_defaults_to_none(self):
        """Test that Route auth_action defaults to None when not specified."""
        class TestController(Controller):
            def index(self):
                pass

        route = Route("get", "/test", TestController, "index")
        self.assertIsNone(route.auth_action)

    def test_route_with_requires_auth_and_auth_action(self):
        """Test that Route correctly stores both requires_auth and auth_action."""
        class TestController(Controller):
            def delete(self):
                pass

        route = Route(
            "delete",
            "/agents/:agent_id",
            TestController,
            "delete",
            requires_auth=True,
            auth_action=Action.DELETE_AGENT,
        )
        self.assertTrue(route.requires_auth)
        self.assertEqual(route.auth_action, Action.DELETE_AGENT)


if __name__ == "__main__":
    unittest.main()
