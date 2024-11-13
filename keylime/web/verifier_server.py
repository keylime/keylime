from functools import wraps

from keylime import config
from keylime.web.base.server import Server
from keylime.web.verifier.agents_controller import AgentsController
from keylime.web.verifier.push_attestation_controller import PushAttestationController


class VerifierServer(Server):
    @Server.push_only
    def _routes(self):
        self._get("/v:version/agents/:agent_id", AgentsController, "show")
        self._post("/v:version/agents", AgentsController, "create")
        self._delete("/v:version/agents/:agent_id", AgentsController, "delete")
        self._post("/v:version/agents/:agent_id/reactivate", AgentsController, "reactivate")
        self._post("/v:version/agents/:agent_id/stop", AgentsController, "stop")
        self._get("/v:version/agents/:agent_id/attestations", PushAttestationController, "index", allow_insecure=True)
        self._get("/v:version/agents/:agent_id/attestations/:index", PushAttestationController, "show",
                  allow_insecure=True)
        self._get("/v:version/agents/:agent_id/attestations/latest", PushAttestationController, "show_latest",
                  allow_insecure=True)
        self._post("/v:version/agents/:agent_id/attestations", PushAttestationController, "create", allow_insecure=True)
        self._put(
            "/v:version/agents/:agent_id/attestations/latest", PushAttestationController, "update", allow_insecure=True
        )

    # Server.pull_only

    # @version_range("1.0", "2.0")
    # def _deprecated_v2_routes(self):
    #     self.post("/v:version/agents/:agent_id", AgentsController, "create")
    #     self.put("/v:version/agents/:agent_id/reactivate", AgentsController, "reactivate")
    #     self.put("/v:version/agents/:agent_id/stop", AgentsController, "stop")
