import unittest
from unittest.mock import patch

from keylime.web.base.server import Server


class _StubServer(Server):
    """Minimal concrete subclass of Server for testing base class properties."""

    def _routes(self):
        pass


class TestWorkerCount(unittest.TestCase):
    """Tests for Server.worker_count property with max_workers cap."""

    def _make_server(self, worker_count=0, max_workers=0):
        """Create a Server instance without triggering __init__ (which binds sockets)."""
        server = _StubServer.__new__(_StubServer)
        # pylint: disable=attribute-defined-outside-init
        setattr(server, "_Server__worker_count", worker_count)
        setattr(server, "_Server__max_workers", max_workers)
        return server

    @patch("keylime.web.base.server.multiprocessing")
    def test_defaults_to_cpu_count(self, mock_mp):
        mock_mp.cpu_count.return_value = 8
        server = self._make_server()
        self.assertEqual(server.worker_count, 8)

    @patch("keylime.web.base.server.multiprocessing")
    def test_capped_by_max_workers(self, mock_mp):
        mock_mp.cpu_count.return_value = 40
        server = self._make_server(max_workers=4)
        self.assertEqual(server.worker_count, 4)

    @patch("keylime.web.base.server.multiprocessing")
    def test_not_capped_when_below_max(self, mock_mp):
        mock_mp.cpu_count.return_value = 8
        server = self._make_server(max_workers=16)
        self.assertEqual(server.worker_count, 8)

    @patch("keylime.web.base.server.multiprocessing")
    def test_max_workers_zero_means_no_limit(self, mock_mp):
        mock_mp.cpu_count.return_value = 64
        server = self._make_server(max_workers=0)
        self.assertEqual(server.worker_count, 64)

    def test_explicit_worker_count_also_capped(self):
        server = self._make_server(worker_count=20, max_workers=8)
        self.assertEqual(server.worker_count, 8)

    def test_explicit_worker_count_not_capped_when_below_max(self):
        server = self._make_server(worker_count=4, max_workers=16)
        self.assertEqual(server.worker_count, 4)

    def test_explicit_worker_count_no_limit(self):
        server = self._make_server(worker_count=20, max_workers=0)
        self.assertEqual(server.worker_count, 20)
