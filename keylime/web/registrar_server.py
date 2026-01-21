from keylime.authorization.provider import Action
from keylime.web.base.server import Server
from keylime.web.registrar.agents_controller import AgentsController
from keylime.web.registrar.version_controller import VersionController


class RegistrarServer(Server):
    def _setup(self):
        self._set_component("registrar")
        self._use_config("registrar")
        self._set_bind_interface(from_config="ip")
        self._set_http_port(from_config="port")
        self._set_https_port(from_config="tls_port")
        self._set_max_upload_size(from_config="max_upload_size")
        self._set_default_ssl_ctx()

    def _routes(self):
        self._v2_routes()
        # Route used by agents to get the supported API versions (public)
        self._get("/version", VersionController, "version", allow_insecure=True, auth_action=Action.READ_VERSION)

    @Server.version_scope(2)
    def _v2_routes(self):
        # Routes used by the tenant/admin to manage registered agents (requires mTLS)
        self._get("/agents", AgentsController, "index", requires_auth=True, auth_action=Action.LIST_REGISTRATIONS)
        self._get(
            "/agents/:agent_id", AgentsController, "show", requires_auth=True, auth_action=Action.READ_REGISTRATION
        )
        self._delete(
            "/agents/:agent_id", AgentsController, "delete", requires_auth=True, auth_action=Action.DELETE_REGISTRATION
        )

        # Routes used by agents to register (public, happens over HTTP without TLS)
        self._post("/agents", AgentsController, "create", allow_insecure=True, auth_action=Action.REGISTER_AGENT)
        self._post(
            "/agents/:agent_id/activate",
            AgentsController,
            "activate",
            allow_insecure=True,
            auth_action=Action.ACTIVATE_AGENT,
        )

        # Routes which are kept for backwards compatibility but do not adhere to RFC 9110 semantics
        self._post(
            "/agents/:agent_id", AgentsController, "create", allow_insecure=True, auth_action=Action.REGISTER_AGENT
        )
        self._put(
            "/agents/:agent_id/activate",
            AgentsController,
            "activate",
            allow_insecure=True,
            auth_action=Action.ACTIVATE_AGENT,
        )
        # Instead of the above documented activation endpoint, the agent currently uses the one below to activate itself
        self._put(
            "/agents/:agent_id", AgentsController, "activate", allow_insecure=True, auth_action=Action.ACTIVATE_AGENT
        )
