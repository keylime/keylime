"""Unit tests for cloud_verifier_tornado helper functions

This module tests the _from_db_obj() function which converts database
objects to dictionaries when restoring agent state after verifier restart.

The test verifies that all VerfierMain database columns are included in
the field list, preventing regressions where fields are accidentally omitted.
"""

import os
import re
import unittest

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


if __name__ == "__main__":
    unittest.main()
