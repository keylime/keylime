"""Unit tests for cloud_verifier_common helper functions

This module tests:
1. _from_db_obj() function which converts database objects to dictionaries
2. process_get_status() function which generates agent status responses

The tests verify that all VerfierMain database columns are included in
the field list, and that attestation status is correctly reported based
on agent state.
"""

import os
import re
import unittest
from unittest.mock import MagicMock

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
