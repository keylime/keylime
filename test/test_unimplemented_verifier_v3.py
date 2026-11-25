import unittest
from typing import cast
from unittest.mock import Mock

from keylime.web.verifier.agent_controller import AgentController
from keylime.web.verifier.evidence_controller import EvidenceController


class TestUnimplementedVerifierV3(unittest.TestCase):
    def _handler(self, path: str) -> Mock:
        handler = Mock()
        handler.request = Mock()
        handler.request.path = path
        handler.request.method = "GET"
        handler.request.headers = {}
        return handler

    def test_agent_index_on_v3_returns_404(self):
        handler = self._handler("/v3.0/agents/")
        controller = cast(AgentController, AgentController(handler))
        controller.index()
        handler.set_status.assert_called_once_with(404, "Not Found")
        handler.finish.assert_called_once()

    def test_evidence_on_v3_returns_404(self):
        handler = self._handler("/v3/verify/evidence")
        controller = cast(EvidenceController, EvidenceController(handler))
        controller.process()
        handler.set_status.assert_called_once_with(404, "Not Found")
        handler.finish.assert_called_once()
