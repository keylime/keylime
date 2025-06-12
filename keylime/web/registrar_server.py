from keylime.web.base.server import Server
from keylime.web.registrar.agents_controller import AgentsController
from keylime.web.registrar.version_controller import VersionController


class RegistrarServer(Server):
    def _setup(self):
        self._use_config("registrar")
        self._set_bind_interface(from_config="ip")
        self._set_http_port(from_config="port")
        self._set_https_port(from_config="tls_port")
        self._set_max_upload_size(from_config="max_upload_size")
        self._set_default_ssl_ctx()

    def _routes(self):
        self._v2_routes()
        # Route used by agents to get the supported API versions
        self._get("/version", VersionController, "version", allow_insecure=True)

    @Server.version_scope(2)
    def _v2_routes(self):
        # Routes used by the tenant to manage registered agents
        self._get("/agents", AgentsController, "index")
        self._get("/agents/:agent_id", AgentsController, "show")
        self._delete("/agents/:agent_id", AgentsController, "delete")

        # Routes used by agents to register (which happens over HTTP without TLS)
        self._post("/agents", AgentsController, "create", allow_insecure=True)
        self._post("/agents/:agent_id/activate", AgentsController, "activate", allow_insecure=True)

        # Routes which are kept for backwards compatibility but do not adhere to RFC 9110 semantics
        self._post("/agents/:agent_id", AgentsController, "create", allow_insecure=True)
        self._put("/agents/:agent_id/activate", AgentsController, "activate", allow_insecure=True)
        # Instead of the above documented activation endpoint, the agent currently uses the one below to activate itself
        self._put("/agents/:agent_id", AgentsController, "activate", allow_insecure=True)
