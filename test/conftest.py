"""Shared pytest fixtures for keylime tests."""

import shutil
import tempfile
from unittest.mock import patch

import pytest

from keylime.shared_data import cleanup_global_shared_memory


@pytest.fixture(autouse=True)
def _shared_data_runtime_dir():
    """Redirect SharedDataManager sockets to a temporary directory.

    The SyncManager creates Unix domain sockets in /var/run/keylime/,
    which may not be writable by the test user.  This fixture patches
    the runtime directory to a per-test temp directory so that tests
    work in any environment.

    After each test, any global SharedDataManager is shut down to
    prevent stale managers from referencing deleted temp directories.
    """
    tmpdir = tempfile.mkdtemp()
    with patch("keylime.shared_data._RUNTIME_DIR", tmpdir):
        yield
    # Shut down any global SharedDataManager left alive by the test
    # so the next test starts fresh with a new temp directory.
    cleanup_global_shared_memory()
    shutil.rmtree(tmpdir, ignore_errors=True)
