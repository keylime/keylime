"""Unit tests for RegistrarServer route configuration.

Tests that v3 routes are correctly registered with the expected controllers,
actions, and auth properties. Also verifies that v3 does not include the
backwards-compatibility routes present in v2, and that v2 routes still work.
"""

import unittest

from keylime.authorization.provider import Action
from keylime.web.registrar.agents_controller import AgentsController
from keylime.web.registrar.version_controller import VersionController
from keylime.web.registrar_server import RegistrarServer


def _create_server():
    """Create a RegistrarServer with routes populated but without binding sockets."""
    server = RegistrarServer.__new__(RegistrarServer)
    server._Server__routes = []  # type: ignore[attr-defined]  # pylint: disable=protected-access
    server._routes()  # pylint: disable=protected-access
    return server


class TestRegistrarServerTopLevelRoutes(unittest.TestCase):
    """Test cases for top-level (unversioned) routes."""

    def setUp(self):
        self.server = _create_server()

    def test_version_route_exists(self):
        """Test that GET /version resolves to VersionController.version."""
        route = self.server.first_matching_route("get", "/version")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, VersionController)
        self.assertEqual(route.action, "version")

    def test_version_route_properties(self):
        """Test that GET /version is public and has correct auth action."""
        route = self.server.first_matching_route("get", "/version")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertTrue(route.allow_insecure)
        self.assertFalse(route.requires_auth)
        self.assertEqual(route.auth_action, Action.READ_VERSION)


class TestRegistrarServerV3Routes(unittest.TestCase):
    """Test cases for v3 route registrations."""

    def setUp(self):
        self.server = _create_server()

    def test_v3_version_root_exists(self):
        """Test that GET /v3/ resolves to VersionController.show_version_root."""
        route = self.server.first_matching_route("get", "/v3/")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, VersionController)
        self.assertEqual(route.action, "show_version_root")

    def test_v3_version_root_properties(self):
        """Test that the v3 version root is public with correct auth action."""
        route = self.server.first_matching_route("get", "/v3/")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertTrue(route.allow_insecure)
        self.assertFalse(route.requires_auth)
        self.assertEqual(route.auth_action, Action.READ_VERSION)

    def test_v3_agents_index(self):
        """Test that GET /v3/agents resolves to AgentsController.index with mTLS required."""
        route = self.server.first_matching_route("get", "/v3/agents")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "index")
        self.assertTrue(route.requires_auth)
        self.assertFalse(route.allow_insecure)
        self.assertEqual(route.auth_action, Action.LIST_REGISTRATIONS)

    def test_v3_agents_show(self):
        """Test that GET /v3/agents/:agent_id resolves to AgentsController.show with mTLS required."""
        route = self.server.first_matching_route("get", "/v3/agents/test-agent-id")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "show")
        self.assertTrue(route.requires_auth)
        self.assertFalse(route.allow_insecure)
        self.assertEqual(route.auth_action, Action.READ_REGISTRATION)

    def test_v3_agents_delete(self):
        """Test that DELETE /v3/agents/:agent_id resolves to AgentsController.delete with mTLS required."""
        route = self.server.first_matching_route("delete", "/v3/agents/test-agent-id")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "delete")
        self.assertTrue(route.requires_auth)
        self.assertFalse(route.allow_insecure)
        self.assertEqual(route.auth_action, Action.DELETE_REGISTRATION)

    def test_v3_agents_create(self):
        """Test that POST /v3/agents resolves to AgentsController.create as a public endpoint."""
        route = self.server.first_matching_route("post", "/v3/agents")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "create")
        self.assertTrue(route.allow_insecure)
        self.assertFalse(route.requires_auth)
        self.assertEqual(route.auth_action, Action.REGISTER_AGENT)

    def test_v3_agents_activate(self):
        """Test that POST /v3/agents/:agent_id/activate resolves to AgentsController.activate as public."""
        route = self.server.first_matching_route("post", "/v3/agents/test-agent-id/activate")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "activate")
        self.assertTrue(route.allow_insecure)
        self.assertFalse(route.requires_auth)
        self.assertEqual(route.auth_action, Action.ACTIVATE_AGENT)

    def test_v3_0_routes_also_match(self):
        """Test that all v3 routes also match with the /v3.0/ prefix."""
        cases = [
            ("get", "/v3.0/", VersionController, "show_version_root"),
            ("get", "/v3.0/agents", AgentsController, "index"),
            ("get", "/v3.0/agents/test-agent-id", AgentsController, "show"),
            ("delete", "/v3.0/agents/test-agent-id", AgentsController, "delete"),
            ("post", "/v3.0/agents", AgentsController, "create"),
            ("post", "/v3.0/agents/test-agent-id/activate", AgentsController, "activate"),
        ]
        for method, path, expected_controller, expected_action in cases:
            with self.subTest(method=method, path=path):
                route = self.server.first_matching_route(method, path)
                self.assertIsNotNone(route, f"No route found for {method.upper()} {path}")
                assert route is not None
                self.assertEqual(route.controller, expected_controller)
                self.assertEqual(route.action, expected_action)


class TestRegistrarServerV3NoCompatRoutes(unittest.TestCase):
    """Test that v3 does NOT include the backwards-compatibility routes from v2.

    V2 includes legacy routes that violate RFC 9110 semantics (e.g., POST with
    agent_id in URL for create, PUT for activate). V3 drops these.
    """

    def setUp(self):
        self.server = _create_server()

    def test_v3_no_post_agents_with_agent_id(self):
        """Test that POST /v3/agents/:agent_id does not resolve (no v2 compat create)."""
        route = self.server.first_matching_route("post", "/v3/agents/some-agent-id")
        self.assertIsNone(route)

    def test_v3_no_put_agents_activate(self):
        """Test that PUT /v3/agents/:agent_id/activate does not resolve (no v2 compat activate)."""
        route = self.server.first_matching_route("put", "/v3/agents/some-agent-id/activate")
        self.assertIsNone(route)

    def test_v3_no_put_agents(self):
        """Test that PUT /v3/agents/:agent_id does not resolve (no v2 compat activate fallback)."""
        route = self.server.first_matching_route("put", "/v3/agents/some-agent-id")
        self.assertIsNone(route)

    def test_v3_0_no_compat_routes(self):
        """Test that v3.0 prefix also has no compat routes."""
        cases = [
            ("post", "/v3.0/agents/some-agent-id"),
            ("put", "/v3.0/agents/some-agent-id/activate"),
            ("put", "/v3.0/agents/some-agent-id"),
        ]
        for method, path in cases:
            with self.subTest(method=method, path=path):
                route = self.server.first_matching_route(method, path)
                self.assertIsNone(route, f"Unexpected compat route found for {method.upper()} {path}")


class TestRegistrarServerV2Routes(unittest.TestCase):
    """Regression tests that v2 routes still resolve correctly."""

    def setUp(self):
        self.server = _create_server()

    def test_v2_agents_index(self):
        """Test that GET /v2/agents resolves to AgentsController.index."""
        route = self.server.first_matching_route("get", "/v2/agents")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "index")

    def test_v2_agents_show(self):
        """Test that GET /v2/agents/:agent_id resolves to AgentsController.show."""
        route = self.server.first_matching_route("get", "/v2/agents/test-agent-id")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "show")

    def test_v2_agents_create(self):
        """Test that POST /v2/agents resolves to AgentsController.create."""
        route = self.server.first_matching_route("post", "/v2/agents")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "create")

    def test_v2_agents_delete(self):
        """Test that DELETE /v2/agents/:agent_id resolves to AgentsController.delete."""
        route = self.server.first_matching_route("delete", "/v2/agents/test-agent-id")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "delete")

    def test_v2_agents_activate(self):
        """Test that POST /v2/agents/:agent_id/activate resolves to AgentsController.activate."""
        route = self.server.first_matching_route("post", "/v2/agents/test-agent-id/activate")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "activate")

    def test_v2_compat_post_agents_agent_id(self):
        """Test that POST /v2/agents/:agent_id resolves to create (v2 compat route)."""
        route = self.server.first_matching_route("post", "/v2/agents/test-agent-id")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "create")

    def test_v2_compat_put_agents_activate(self):
        """Test that PUT /v2/agents/:agent_id/activate resolves to activate (v2 compat route)."""
        route = self.server.first_matching_route("put", "/v2/agents/test-agent-id/activate")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "activate")

    def test_v2_compat_put_agents_agent_id(self):
        """Test that PUT /v2/agents/:agent_id resolves to activate (v2 compat fallback)."""
        route = self.server.first_matching_route("put", "/v2/agents/test-agent-id")
        self.assertIsNotNone(route)
        assert route is not None
        self.assertEqual(route.controller, AgentsController)
        self.assertEqual(route.action, "activate")


if __name__ == "__main__":
    unittest.main()
