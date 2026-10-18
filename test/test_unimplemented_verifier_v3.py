import unittest
from unittest.mock import Mock

from keylime.web.verifier.agent_controller import AgentController
from keylime.web.verifier.evidence_controller import EvidenceController


class TestUnimplementedVerifierV3(unittest.TestCase):
    def _controller(self, cls, path):
        handler = Mock()
        handler.request = Mock()
        handler.request.path = path
        handler.request.method = "GET"
        handler.request.headers = {}
        return cls(handler), handler

    def test_agent_index_on_v3_returns_404(self):
        controller, handler = self._controller(AgentController, "/v3.0/agents/")
        controller.index()
        handler.set_status.assert_called_once_with(404, "Not Found")
        handler.finish.assert_called_once()

    def test_evidence_on_v3_returns_404(self):
        controller, handler = self._controller(EvidenceController, "/v3/verify/evidence")
        controller.process()
        handler.set_status.assert_called_once_with(404, "Not Found")
        handler.finish.assert_called_once()
