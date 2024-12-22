from functools import wraps

from keylime import config
from keylime.web.base.server import Server
from keylime.web.verifier.agents_controller import AgentsController
from keylime.web.verifier.push_attestation_controller import PushAttestationController


class VerifierServer(Server):
    @Server.push_only
    def _routes(self):
        # AGENT RESOURCES
        # self._post("/agents", AgentsController, "create")
        # self._get("/agents/:agent_id", AgentsController, "show")
        # self._delete("/agents/:agent_id", AgentsController, "delete")
        # self._post("/agents/:agent_id/stop", AgentsController, "stop")
        # self._post("/agents/:agent_id/reactivate", AgentsController, "reactivate")

        # ATTESTATION RESOURCES
        self._get("/agents/:agent_id/attestations", PushAttestationController, "index")
        self._post("/agents/:agent_id/attestations", PushAttestationController, "create")
        self._get("/agents/:agent_id/attestations/latest", PushAttestationController, "show_latest")
        self._patch("/agents/:agent_id/attestations/latest", PushAttestationController, "update_latest")
        self._get("/agents/:agent_id/attestations/:index", PushAttestationController, "show")
        self._patch("/agents/:agent_id/attestations/:index", PushAttestationController, "update")
