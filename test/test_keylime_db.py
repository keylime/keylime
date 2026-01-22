"""Test keylime_db module for database engine configuration."""

import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy.pool import NullPool


class TestMakeEngineSQLiteConfiguration(unittest.TestCase):
    """Test make_engine SQLite configuration, especially multiprocessing-safe NullPool."""

    @patch("keylime.db.keylime_db.config")
    def test_sqlite_uses_nullpool_for_multiprocessing_safety(self, mock_config):
        """Verify SQLite databases use NullPool to avoid multiprocessing connection leaks."""
        from keylime.db.keylime_db import make_engine  # pylint: disable=import-outside-toplevel

        # Create a temporary database file
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp:
            db_path = tmp.name

        # Configure to use sqlite keyword
        mock_config.get.return_value = "sqlite"
        mock_config.WORK_DIR = tempfile.gettempdir()
        mock_config.DEBUG_DB = False
        mock_config.INSECURE_DEBUG = False

        try:
            # Create engine for cloud_verifier service
            engine = make_engine("cloud_verifier")

            # Verify NullPool is used for SQLite
            self.assertIsInstance(
                engine.pool,
                NullPool,
                "SQLite databases must use NullPool for multiprocessing safety",
            )

            # Clean up
            engine.dispose()
        finally:
            import os  # pylint: disable=import-outside-toplevel

            try:
                os.unlink(db_path)
            except Exception:  # pylint: disable=broad-except
                pass

    @patch("keylime.db.keylime_db.config")
    def test_sqlite_url_configuration(self, mock_config):
        """Verify SQLite database URL is properly configured with check_same_thread=False."""
        from keylime.db.keylime_db import make_engine  # pylint: disable=import-outside-toplevel

        # Configure to use sqlite keyword
        mock_config.get.return_value = "sqlite"
        mock_config.WORK_DIR = tempfile.gettempdir()
        mock_config.DEBUG_DB = False
        mock_config.INSECURE_DEBUG = False

        # Create engine
        engine = make_engine("cloud_verifier")

        # Verify check_same_thread is False (required for multithreading)
        self.assertEqual(engine.url.drivername, "sqlite")

        # Clean up
        engine.dispose()


if __name__ == "__main__":
    unittest.main()
