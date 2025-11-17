"""Unit tests for cloud_verifier_common helper functions

This module tests:
1. _from_db_obj() function which converts database objects to dictionaries
2. process_get_status() function which generates agent status responses

The tests verify that all VerfierMain database columns are included in
the field list, and that attestation status is correctly reported based
on agent state.

It also tests the singleton SessionManager initialization for thread safety
and verifies SQLAlchemy 2.0 API compliance.
"""

import os
import re
import threading
import unittest
from unittest.mock import MagicMock, patch

from keylime import cloud_verifier_common
from keylime.common import states
from keylime.db.verifier_db import VerfierMain


class TestFromDbObjFieldList(unittest.TestCase):
    """Test that _from_db_obj() field list matches VerfierMain columns.

    This test ensures that all database fields are properly included in the
    _from_db_obj() function's field list. Without this check, fields can be
    accidentally omitted, causing regressions where agent state is not fully
    restored after verifier restart.

    This is a source code analysis test - it reads the _from_db_obj function
    source and verifies all VerfierMain columns are in the field list.
    """

    def test_from_db_obj_field_list_includes_all_columns(self):
        """Verify _from_db_obj() field list includes all VerfierMain columns.

        Reads the source code of _from_db_obj() and checks that all database
        columns from VerfierMain are present in its field list.

        Regression test for: accept_attestations field missing from field list,
        causing it not to be restored after verifier restart (reported in
        keylime-tests PR #923).
        """
        # Get all column names from VerfierMain
        db_columns = set()
        for column in VerfierMain.__table__.columns:
            db_columns.add(column.name)

        # Read the source code of _from_db_obj from cloud_verifier_tornado.py
        verifier_tornado_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "cloud_verifier_tornado.py")

        with open(verifier_tornado_path, encoding="utf-8") as f:
            source = f.read()

        # Find the _from_db_obj function and extract its field list
        # Look for the pattern: fields = [ ... ]
        # Match the fields list in _from_db_obj function
        pattern = r"def _from_db_obj.*?fields = \[(.*?)\]"
        match = re.search(pattern, source, re.DOTALL)

        self.assertIsNotNone(match, "_from_db_obj function or fields list not found in source code")
        assert match is not None  # Type narrowing for pyright

        fields_block = match.group(1)

        # Extract all field names (strings in quotes)
        field_pattern = r'"([^"]+)"'
        fields_in_code = set(re.findall(field_pattern, fields_block))

        # Check that all database columns are in the field list
        # Some columns may be excluded from the field list (like id), but
        # critical state fields MUST be included
        missing_fields = []
        critical_fields = [
            "agent_id",
            "v",
            "ip",
            "port",
            "operational_state",
            "public_key",
            "tpm_policy",
            "meta_data",
            "ima_sign_verification_keys",
            "revocation_key",
            "accept_tpm_hash_algs",
            "accept_tpm_encryption_algs",
            "accept_tpm_signing_algs",
            "hash_alg",
            "enc_alg",
            "sign_alg",
            "boottime",
            "ima_pcrs",
            "pcr10",
            "next_ima_ml_entry",
            "learned_ima_keyrings",
            "supported_version",
            "mtls_cert",
            "ak_tpm",
            "attestation_count",
            "last_received_quote",
            "last_successful_attestation",
            "tpm_clockinfo",
            "accept_attestations",  # Critical for push-attestation mode
        ]

        for field in critical_fields:
            if field in db_columns and field not in fields_in_code:
                missing_fields.append(field)

        if missing_fields:
            self.fail(
                f"Critical database fields missing from _from_db_obj() field list: {missing_fields}. "
                f"These fields will not be restored after verifier restart, causing state loss. "
                f"Add them to the fields list in cloud_verifier_tornado.py:_from_db_obj()"
            )

        # Specifically check for accept_attestations (the bug this test catches)
        self.assertIn(
            "accept_attestations",
            fields_in_code,
            "accept_attestations field MUST be in _from_db_obj() field list. "
            "Without it, push-attestation mode will fail after verifier restart. "
            "See keylime-tests PR #923 for details.",
        )


class TestSessionManagerSingleton(unittest.TestCase):
    """Test singleton SessionManager initialization with thread safety.

    These tests verify that the _initialize_verifier_config() function
    properly initializes the global _session_manager singleton with
    thread-safe double-checked locking.

    Regression test for: Race condition causing multiple SessionManager
    instances to be created, defeating SQLAlchemy's scoped_session
    mechanism and causing connection pool thrashing.
    """

    def setUp(self):
        """Reset the module-level singleton state before each test."""
        # Import here to avoid circular dependencies
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Reset the initialization state
        # pylint: disable=protected-access
        cvt._verifier_config_initialized = False
        cvt._session_manager = None
        cvt.engine = None
        # pylint: enable=protected-access

    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.record")
    def test_singleton_initialization_creates_session_manager(
        self, mock_record, mock_make_engine, mock_config, _mock_set_severity
    ):
        """Verify _initialize_verifier_config() creates singleton SessionManager."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = ""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine
        mock_record.get_record_mgt_class.return_value = None

        # Initially None
        # pylint: disable=protected-access
        self.assertIsNone(cvt._session_manager)
        self.assertFalse(cvt._verifier_config_initialized)

        # Initialize
        cvt._initialize_verifier_config()

        # Should now be initialized
        self.assertIsNotNone(cvt._session_manager)
        self.assertTrue(cvt._verifier_config_initialized)
        self.assertIsNotNone(cvt.engine)
        # pylint: enable=protected-access

    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.record")
    def test_singleton_initialization_is_idempotent(
        self, mock_record, mock_make_engine, mock_config, _mock_set_severity
    ):
        """Verify multiple calls to _initialize_verifier_config() don't create new instances."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = ""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine
        mock_record.get_record_mgt_class.return_value = None

        # First initialization
        # pylint: disable=protected-access
        cvt._initialize_verifier_config()
        first_manager = cvt._session_manager
        first_engine = cvt.engine

        # Second initialization
        cvt._initialize_verifier_config()
        second_manager = cvt._session_manager
        second_engine = cvt.engine
        # pylint: enable=protected-access

        # Should be the same instances (singleton)
        self.assertIs(first_manager, second_manager)
        self.assertIs(first_engine, second_engine)

    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.record")
    def test_singleton_initialization_thread_safety(
        self, mock_record, mock_make_engine, mock_config, _mock_set_severity
    ):
        """Verify concurrent initialization from multiple threads creates only one instance."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = ""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine
        mock_record.get_record_mgt_class.return_value = None

        managers_created = []
        barrier = threading.Barrier(10)  # Synchronize 10 threads

        def init_in_thread():
            # Wait for all threads to be ready
            barrier.wait()
            # All threads initialize simultaneously
            # pylint: disable=protected-access
            cvt._initialize_verifier_config()
            # Record the manager instance they see
            managers_created.append(cvt._session_manager)
            # pylint: enable=protected-access

        # Create 10 threads that all try to initialize
        threads = []
        for _ in range(10):
            t = threading.Thread(target=init_in_thread)
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # All threads should see the same singleton instance
        self.assertEqual(len(managers_created), 10)
        unique_managers = set(id(m) for m in managers_created)
        self.assertEqual(len(unique_managers), 1, "Thread safety violation: Multiple SessionManager instances created")


class TestSessionContextExecution(unittest.TestCase):
    """Test actual execution of session_context() with singleton SessionManager.

    These tests actually execute the code (not just analyze it) to provide
    coverage metrics, verifying that session_context() uses the singleton
    _session_manager instance.
    """

    def setUp(self):
        """Reset singleton state before each test."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # pylint: disable=protected-access
        cvt._verifier_config_initialized = False
        cvt._session_manager = None
        cvt.engine = None
        # pylint: enable=protected-access

    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.record")
    def test_session_context_uses_singleton_session_manager(
        self, mock_record, mock_make_engine, mock_config, _mock_set_severity
    ):
        """Verify session_context() uses the singleton _session_manager."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = ""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine
        mock_record.get_record_mgt_class.return_value = None

        # Mock SessionManager's session_context to avoid actual database operations
        mock_session = MagicMock()
        with patch("keylime.cloud_verifier_tornado.SessionManager") as MockSessionManager:
            mock_sm_instance = MagicMock()
            MockSessionManager.return_value = mock_sm_instance
            mock_sm_instance.session_context.return_value.__enter__.return_value = mock_session
            mock_sm_instance.session_context.return_value.__exit__.return_value = None

            # Call session_context() which should trigger initialization
            with cvt.session_context() as session:
                self.assertIs(session, mock_session)

            # Verify SessionManager was created as singleton
            # pylint: disable=protected-access
            self.assertIsNotNone(cvt._session_manager)
            self.assertTrue(cvt._verifier_config_initialized)
            # pylint: enable=protected-access

            # Verify SessionManager instance was created once
            MockSessionManager.assert_called_once()

    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.record")
    def test_session_context_reuses_singleton_on_multiple_calls(
        self, mock_record, mock_make_engine, mock_config, _mock_set_severity
    ):
        """Verify multiple session_context() calls reuse the same singleton SessionManager."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = ""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine
        mock_record.get_record_mgt_class.return_value = None

        # Mock SessionManager
        mock_session = MagicMock()
        with patch("keylime.cloud_verifier_tornado.SessionManager") as MockSessionManager:
            mock_sm_instance = MagicMock()
            MockSessionManager.return_value = mock_sm_instance
            mock_sm_instance.session_context.return_value.__enter__.return_value = mock_session
            mock_sm_instance.session_context.return_value.__exit__.return_value = None

            # First call to session_context()
            with cvt.session_context() as session1:
                self.assertIs(session1, mock_session)

            # pylint: disable=protected-access
            first_sm = cvt._session_manager
            # pylint: enable=protected-access

            # Second call to session_context() should reuse singleton
            with cvt.session_context() as session2:
                self.assertIs(session2, mock_session)

            # pylint: disable=protected-access
            second_sm = cvt._session_manager
            # pylint: enable=protected-access

            # Should be the same singleton instance
            self.assertIs(first_sm, second_sm)

            # SessionManager() should only be called once (singleton)
            MockSessionManager.assert_called_once()


class TestStoreAttestationStateExecution(unittest.TestCase):
    """Test actual execution of store_attestation_state() using SQLAlchemy 2.0 API.

    These tests execute the modified store_attestation_state() function to ensure
    it uses session.get() instead of deprecated query().get().
    """

    @patch("keylime.cloud_verifier_tornado.session_context")
    @patch("keylime.cloud_verifier_tornado.logger")
    def test_store_attestation_state_executes_with_session_get(self, _mock_logger, mock_session_context):
        """Verify store_attestation_state() executes and uses session.get()."""
        from keylime.cloud_verifier_tornado import (  # pylint: disable=import-outside-toplevel
            AgentAttestState,
            store_attestation_state,
        )

        # Create mock session
        mock_session = MagicMock()
        mock_session_context.return_value.__enter__.return_value = mock_session
        mock_session_context.return_value.__exit__.return_value = None

        # Create mock agent from database
        mock_agent = MagicMock()
        mock_session.get.return_value = mock_agent

        # Create mock attestation state
        mock_state = MagicMock(spec=AgentAttestState)
        # Set both attribute and method for agent_id (code uses both)
        mock_state.agent_id = "test_agent_123"
        mock_state.get_agent_id.return_value = "test_agent_123"
        mock_state.get_boottime.return_value = 12345
        mock_state.get_next_ima_ml_entry.return_value = 100
        mock_state.get_ima_pcrs.return_value = {10: "abc123"}
        mock_ima_keyrings = MagicMock()
        mock_ima_keyrings.to_json.return_value = '{"keyrings": []}'
        mock_state.get_ima_keyrings.return_value = mock_ima_keyrings

        # Execute store_attestation_state
        store_attestation_state(mock_state)

        # Verify session.get() was called with correct arguments (SQLAlchemy 2.0 API)
        mock_session.get.assert_called_once_with(VerfierMain, "test_agent_123")

        # Verify attributes were set
        self.assertEqual(mock_agent.boottime, 12345)
        self.assertEqual(mock_agent.next_ima_ml_entry, 100)
        self.assertEqual(mock_agent.ima_pcrs, [10])
        self.assertEqual(mock_agent.pcr10, "abc123")
        self.assertEqual(mock_agent.learned_ima_keyrings, '{"keyrings": []}')

        # Verify session.add was called
        mock_session.add.assert_called_once_with(mock_agent)

    @patch("keylime.cloud_verifier_tornado.session_context")
    @patch("keylime.cloud_verifier_tornado.logger")
    def test_store_attestation_state_handles_exception(self, mock_logger, mock_session_context):
        """Verify store_attestation_state() handles SQLAlchemy exceptions."""
        from sqlalchemy.exc import SQLAlchemyError  # pylint: disable=import-outside-toplevel

        from keylime.cloud_verifier_tornado import (  # pylint: disable=import-outside-toplevel
            AgentAttestState,
            store_attestation_state,
        )

        # Create mock session that raises exception
        mock_session = MagicMock()
        mock_session_context.return_value.__enter__.return_value = mock_session
        mock_session_context.return_value.__exit__.return_value = None
        mock_session.get.side_effect = SQLAlchemyError("Database error")

        # Create mock attestation state
        mock_state = MagicMock(spec=AgentAttestState)
        # Set both attribute and method for agent_id (code uses both)
        mock_state.agent_id = "test_agent_456"
        mock_state.get_agent_id.return_value = "test_agent_456"
        mock_state.get_ima_pcrs.return_value = {10: "abc123"}  # Needed to enter if block

        # Execute store_attestation_state - should handle exception gracefully
        store_attestation_state(mock_state)

        # Verify error was logged
        mock_logger.error.assert_called()


class TestInitializeVerifierConfigExecution(unittest.TestCase):
    """Test actual execution of _initialize_verifier_config() with all code paths.

    These tests execute the initialization to cover all branches including
    fast path, lock acquisition, and double-checked locking.
    """

    def setUp(self):
        """Reset singleton state before each test."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # pylint: disable=protected-access
        cvt._verifier_config_initialized = False
        cvt._session_manager = None
        cvt.engine = None
        # pylint: enable=protected-access

    @patch("keylime.cloud_verifier_tornado.record")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    def test_initialize_verifier_config_fast_path(self, _mock_set_severity, mock_config, mock_make_engine, mock_record):
        """Verify fast path when already initialized (no lock acquisition)."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = ""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine
        mock_record.get_record_mgt_class.return_value = None

        # First initialization
        # pylint: disable=protected-access
        cvt._initialize_verifier_config()
        first_call_count = mock_make_engine.call_count

        # Second call should hit fast path (line 77) - no lock, no re-initialization
        cvt._initialize_verifier_config()
        second_call_count = mock_make_engine.call_count
        # pylint: enable=protected-access

        # make_engine should only be called once (fast path avoids re-initialization)
        self.assertEqual(first_call_count, 1)
        self.assertEqual(second_call_count, 1)  # No additional call

    @patch("keylime.cloud_verifier_tornado.record")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    def test_initialize_verifier_config_with_record_manager(
        self, _mock_set_severity, mock_config, mock_make_engine, mock_record
    ):
        """Verify initialization with record manager configured."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration with record manager
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = "test_record_class"
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        # Mock record manager class
        mock_rmc_class = MagicMock()
        mock_rmc_instance = MagicMock()
        mock_rmc_class.return_value = mock_rmc_instance
        mock_record.get_record_mgt_class.return_value = mock_rmc_class

        # Initialize
        # pylint: disable=protected-access
        cvt._initialize_verifier_config()
        # pylint: enable=protected-access

        # Verify record manager was initialized (lines 94-96)
        mock_record.get_record_mgt_class.assert_called_once_with("test_record_class")
        mock_rmc_class.assert_called_once_with("verifier")

        # Verify rmc was set
        self.assertEqual(cvt.rmc, mock_rmc_instance)


class TestSQLAlchemy20APIUsage(unittest.TestCase):
    """Test SQLAlchemy 2.0 API compliance.

    These tests verify that the code uses SQLAlchemy 2.0 syntax instead of
    deprecated 1.x patterns, particularly session.get() instead of
    session.query().get().

    Regression test for: Database errors with SQLAlchemy 2.0.39+ caused by
    using deprecated Query.get() method.
    """

    def test_no_deprecated_query_get_usage(self):
        """Verify cloud_verifier_tornado.py doesn't use deprecated session.query().get()."""
        # Read the source code
        verifier_tornado_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "cloud_verifier_tornado.py")

        with open(verifier_tornado_path, encoding="utf-8") as f:
            source = f.read()

        # Look for the deprecated pattern: session.query(...).get(
        # This pattern is deprecated in SQLAlchemy 2.0 and causes errors
        deprecated_pattern = r"session\.query\([^)]+\)\.get\("

        matches = re.findall(deprecated_pattern, source)

        if matches:
            self.fail(
                f"Found deprecated session.query().get() usage in cloud_verifier_tornado.py. "
                f"This causes errors with SQLAlchemy 2.0.39+. "
                f"Use session.get(Model, id) instead. "
                f"Matches found: {matches}"
            )

    def test_uses_sqlalchemy_20_session_get(self):
        """Verify cloud_verifier_tornado.py uses SQLAlchemy 2.0 session.get() API."""
        # Read the source code
        verifier_tornado_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "cloud_verifier_tornado.py")

        with open(verifier_tornado_path, encoding="utf-8") as f:
            source = f.read()

        # Look for the SQLAlchemy 2.0 pattern: session.get(Model, id)
        # This should appear in store_attestation_state() and AgentsHandler.delete()
        modern_pattern = r"session\.get\(VerfierMain,"

        matches = re.findall(modern_pattern, source)

        # We expect at least 2 occurrences (store_attestation_state and AgentsHandler.delete)
        self.assertGreaterEqual(
            len(matches),
            2,
            f"Expected at least 2 uses of session.get(VerfierMain, ...) in cloud_verifier_tornado.py, "
            f"found {len(matches)}. The SQLAlchemy 2.0 API should be used instead of deprecated Query.get().",
        )

    def test_store_attestation_state_uses_session_get(self):
        """Verify store_attestation_state() uses session.get() not query().get()."""
        # Read the source code
        verifier_tornado_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "cloud_verifier_tornado.py")

        with open(verifier_tornado_path, encoding="utf-8") as f:
            source = f.read()

        # Find the store_attestation_state function
        pattern = r"def store_attestation_state\(.*?\):(.*?)(?=\ndef |\Z)"
        match = re.search(pattern, source, re.DOTALL)

        self.assertIsNotNone(match, "store_attestation_state function not found")
        assert match is not None

        function_body = match.group(1)

        # Should use session.get(VerfierMain, ...)
        self.assertIn(
            "session.get(VerfierMain,",
            function_body,
            "store_attestation_state should use session.get(VerfierMain, id) per SQLAlchemy 2.0 API",
        )

        # Should NOT use deprecated session.query().get()
        self.assertNotIn(
            ".query(VerfierMain).get(",
            function_body,
            "store_attestation_state should not use deprecated query().get() method",
        )


class TestAgentsHandlerDeleteCodeAnalysis(unittest.TestCase):
    """Test AgentsHandler.delete() uses SQLAlchemy 2.0 API via source code analysis.

    These tests verify the code structure to ensure session.get() is used
    instead of deprecated query().get() in AgentsHandler.delete().
    """

    def test_agents_handler_delete_uses_session_get(self):
        """Verify AgentsHandler.delete() uses session.get() not deprecated query().get()."""
        # Read the source code
        verifier_tornado_path = os.path.join(os.path.dirname(__file__), "..", "keylime", "cloud_verifier_tornado.py")

        with open(verifier_tornado_path, encoding="utf-8") as f:
            source = f.read()

        # Find lines around session.get in AgentsHandler context
        # Looking for the specific pattern: update_agent = session.get(VerfierMain, agent_id)
        # This appears in the delete method at line 554

        # Check that the modified line exists (SQLAlchemy 2.0 API)
        self.assertIn(
            "update_agent = session.get(VerfierMain, agent_id)",
            source,
            "AgentsHandler.delete should use session.get(VerfierMain, agent_id) per SQLAlchemy 2.0 API",
        )

        # Ensure it's in the context of AgentsHandler class
        # Find the AgentsHandler class and verify it contains session.get
        agents_handler_start = source.find("class AgentsHandler")
        self.assertNotEqual(agents_handler_start, -1, "AgentsHandler class not found")

        # Find the next class after AgentsHandler to define the boundary
        next_class = source.find("\nclass ", agents_handler_start + 1)
        agents_handler_section = source[agents_handler_start : next_class if next_class != -1 else len(source)]

        # Verify session.get is in AgentsHandler
        self.assertIn(
            "session.get(VerfierMain, agent_id)", agents_handler_section, "session.get() must be used in AgentsHandler"
        )


class TestSessionContextEdgeCases(unittest.TestCase):
    """Test edge cases and error handling in session_context()."""

    def setUp(self):
        """Reset singleton state before each test."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # pylint: disable=protected-access
        cvt._verifier_config_initialized = False
        cvt._session_manager = None
        cvt.engine = None
        # pylint: enable=protected-access

    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.record")
    @patch("keylime.cloud_verifier_tornado.SessionManager")
    def test_session_context_assertion_on_uninitialized(
        self, MockSessionManager, mock_record, mock_make_engine, mock_config, _mock_set_severity
    ):
        """Verify session_context() asserts when session_manager is None (edge case)."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = ""
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine
        mock_record.get_record_mgt_class.return_value = None

        # Mock SessionManager to return None (simulating initialization failure)
        MockSessionManager.return_value = None

        # Force initialization
        # pylint: disable=protected-access
        cvt._initialize_verifier_config()

        # session_context should assert when _session_manager is None
        with self.assertRaises(AssertionError):
            with cvt.session_context():
                pass
        # pylint: enable=protected-access


class TestInitializeVerifierConfigErrorPaths(unittest.TestCase):
    """Test error handling paths in _initialize_verifier_config()."""

    def setUp(self):
        """Reset singleton state before each test."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # pylint: disable=protected-access
        cvt._verifier_config_initialized = False
        cvt._session_manager = None
        cvt.engine = None
        # pylint: enable=protected-access

    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.sys")
    def test_initialize_verifier_config_sqlalchemy_error(
        self, mock_sys, mock_make_engine, mock_config, _mock_set_severity
    ):
        """Verify _initialize_verifier_config() handles SQLAlchemy errors."""
        from sqlalchemy.exc import SQLAlchemyError  # pylint: disable=import-outside-toplevel

        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = ""

        # Mock make_engine to raise SQLAlchemyError
        mock_make_engine.side_effect = SQLAlchemyError("Database connection failed")
        mock_sys.exit = MagicMock()  # Mock sys.exit to prevent actual exit

        # Initialize - should catch exception and call sys.exit(1)
        # pylint: disable=protected-access
        cvt._initialize_verifier_config()
        # pylint: enable=protected-access

        # Verify sys.exit(1) was called
        mock_sys.exit.assert_called_once_with(1)

    @patch("keylime.cloud_verifier_tornado.set_severity_config")
    @patch("keylime.cloud_verifier_tornado.config")
    @patch("keylime.cloud_verifier_tornado.make_engine")
    @patch("keylime.cloud_verifier_tornado.record")
    @patch("keylime.cloud_verifier_tornado.sys")
    def test_initialize_verifier_config_record_management_error(
        self, mock_sys, mock_record, mock_make_engine, mock_config, _mock_set_severity
    ):
        """Verify _initialize_verifier_config() handles record management errors."""
        import keylime.cloud_verifier_tornado as cvt  # pylint: disable=import-outside-toplevel

        # Mock configuration
        mock_config.getlist.return_value = ["info", "error"]
        mock_config.get.return_value = "invalid_record_class"
        mock_engine = MagicMock()
        mock_make_engine.return_value = mock_engine

        # Create a custom exception class to simulate RecordManagementException
        class MockRecordManagementException(Exception):
            pass

        # Mock record manager to raise exception
        mock_record.RecordManagementException = MockRecordManagementException
        mock_record.get_record_mgt_class.side_effect = MockRecordManagementException("Invalid record class")
        mock_sys.exit = MagicMock()  # Mock sys.exit

        # Initialize - should catch exception and call sys.exit(1)
        # pylint: disable=protected-access
        cvt._initialize_verifier_config()
        # pylint: enable=protected-access

        # Verify sys.exit(1) was called
        mock_sys.exit.assert_called_once_with(1)


class TestProcessGetStatus(unittest.TestCase):
    """Test process_get_status() attestation status logic.

    This test verifies that attestation_status is correctly determined based on:
    - PUSH mode: accept_attestations flag AND attestation history
    - PULL mode: operational_state

    Regression test for: PUSH mode agents showing PASS status before first attestation
    """

    def _create_mock_agent(
        self,
        operational_state=None,
        ip=None,
        port=None,
        accept_attestations=True,
        attestation_count=0,
    ):
        """Helper to create a mock agent with specified attributes."""
        agent = MagicMock(spec=VerfierMain)
        agent.operational_state = operational_state
        agent.ip = ip
        agent.port = port
        agent.accept_attestations = accept_attestations
        agent.attestation_count = attestation_count
        agent.last_received_quote = 0
        agent.last_successful_attestation = 0
        agent.v = None
        agent.tpm_policy = "{}"
        agent.meta_data = "{}"
        agent.mb_policy = MagicMock()
        agent.mb_policy.mb_policy = None
        agent.ima_policy = MagicMock()
        agent.ima_policy.generator = 0
        agent.accept_tpm_hash_algs = ["sha256"]
        agent.accept_tpm_encryption_algs = ["rsa"]
        agent.accept_tpm_signing_algs = ["rsassa"]
        agent.hash_alg = ""
        agent.enc_alg = ""
        agent.sign_alg = ""
        agent.verifier_id = "default"
        agent.verifier_ip = "127.0.0.1"
        agent.verifier_port = 8881
        agent.severity_level = None
        agent.last_event_id = None
        return agent

    def test_push_mode_agent_pending_before_first_attestation(self):
        """Test PUSH mode agent shows PENDING before first attestation."""
        # Create PUSH mode agent (ip=None, port=None)
        # with accept_attestations=True but attestation_count=0
        agent = self._create_mock_agent(
            operational_state=states.GET_QUOTE,  # PUSH mode sets this
            ip=None,
            port=None,
            accept_attestations=True,
            attestation_count=0,  # Never attested
        )

        status = cloud_verifier_common.process_get_status(agent)

        # Should be PENDING because agent has never attested
        self.assertEqual(
            status["attestation_status"],
            "PENDING",
            "PUSH mode agent should show PENDING before first attestation, even if accept_attestations=True",
        )

    def test_push_mode_agent_pass_after_attestation(self):
        """Test PUSH mode agent shows PASS after successful attestation."""
        # Create PUSH mode agent with attestation_count > 0
        agent = self._create_mock_agent(
            operational_state=states.GET_QUOTE,
            ip=None,
            port=None,
            accept_attestations=True,
            attestation_count=1,  # Has attested
        )

        status = cloud_verifier_common.process_get_status(agent)

        # Should be PASS because agent has attested and accept_attestations=True
        self.assertEqual(
            status["attestation_status"],
            "PASS",
            "PUSH mode agent should show PASS after successful attestation",
        )

    def test_push_mode_agent_fail_when_not_accepting(self):
        """Test PUSH mode agent shows FAIL when accept_attestations=False."""
        # Create PUSH mode agent with accept_attestations=False
        agent = self._create_mock_agent(
            operational_state=states.GET_QUOTE,
            ip=None,
            port=None,
            accept_attestations=False,  # Timed out or failed
            attestation_count=1,
        )

        status = cloud_verifier_common.process_get_status(agent)

        # Should be FAIL because accept_attestations=False
        self.assertEqual(
            status["attestation_status"],
            "FAIL",
            "PUSH mode agent should show FAIL when accept_attestations=False",
        )

    def test_pull_mode_agent_pass_in_get_quote_state(self):
        """Test PULL mode agent shows PASS in GET_QUOTE state."""
        # Create PULL mode agent (has ip and port)
        agent = self._create_mock_agent(
            operational_state=states.GET_QUOTE,
            ip="127.0.0.1",
            port=9002,
            attestation_count=0,  # PULL mode doesn't check this
        )

        status = cloud_verifier_common.process_get_status(agent)

        # Should be PASS because operational_state is GET_QUOTE
        self.assertEqual(
            status["attestation_status"],
            "PASS",
            "PULL mode agent should show PASS in GET_QUOTE state",
        )

    def test_pull_mode_agent_pending_in_start_state(self):
        """Test PULL mode agent shows PENDING in START state."""
        # Create PULL mode agent in START state
        agent = self._create_mock_agent(
            operational_state=states.START,
            ip="127.0.0.1",
            port=9002,
        )

        status = cloud_verifier_common.process_get_status(agent)

        # Should be PENDING because operational_state is START
        self.assertEqual(
            status["attestation_status"],
            "PENDING",
            "PULL mode agent should show PENDING in START state",
        )

    def test_pull_mode_agent_fail_in_failed_state(self):
        """Test PULL mode agent shows FAIL in FAILED state."""
        # Create PULL mode agent in FAILED state
        agent = self._create_mock_agent(
            operational_state=states.FAILED,
            ip="127.0.0.1",
            port=9002,
        )

        status = cloud_verifier_common.process_get_status(agent)

        # Should be FAIL because operational_state is FAILED
        self.assertEqual(
            status["attestation_status"],
            "FAIL",
            "PULL mode agent should show FAIL in FAILED state",
        )


if __name__ == "__main__":
    unittest.main()
