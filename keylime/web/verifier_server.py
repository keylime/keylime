from keylime.web.base.server import Server
from keylime.web.verifier.agents_controller import AgentsController
from keylime.web.verifier.pushAttestation_controller import PushAttestation

class VerifierServer(Server):
    
    def _routes(self):
        # _deprecated_v2_routes

        self._get("/v:version/agents/:agent_id", AgentsController, "show")
        self._post("/v:version/agents", AgentsController, "create")
        self._delete("/v:version/agents/:agent_id", AgentsController, "delete")
        self._post("/v:version/agents/:agent_id/reactivate", AgentsController, "reactivate")
        self._post("/v:version/agents/:agent_id/stop", AgentsController, "stop")
        self._post("/v:version/agents/:agent_id/attestations", PushAttestation, "create", allow_insecure = True)
        self._get("/v:version/agents/:agent_id/attestations", PushAttestation, "show", allow_insecure = True)
        self._put("/v:version/agents/:agent_id/attestations/latest", PushAttestation, "update", allow_insecure = True)

    # @version_range("1.0", "2.0")
    # def _deprecated_v2_routes(self):
    #     self.post("/v:version/agents/:agent_id", AgentsController, "create")
    #     self.put("/v:version/agents/:agent_id/reactivate", AgentsController, "reactivate")
    #     self.put("/v:version/agents/:agent_id/stop", AgentsController, "stop")