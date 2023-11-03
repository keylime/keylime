import unittest

from keylime import agentstates


class TestAgentStates(unittest.TestCase):
    def test_check_quote_progress(self):
        aas = agentstates.AgentAttestState("1")
        self.assertTrue(aas.check_quote_progress(9, 10))  # lag 1
        self.assertFalse(aas.check_quote_progress(0, 1))  # still lag 1
        self.assertTrue(aas.check_quote_progress(1, 1))  # lag 0

        aas.reset_ima_attestation()
        self.assertTrue(aas.check_quote_progress(10, 10))  # lag 0
        self.assertTrue(aas.check_quote_progress(0, 1))  # lag 1
        self.assertFalse(aas.check_quote_progress(0, 1))  # still lag 1
        self.assertTrue(aas.check_quote_progress(0, 0))  # lag 0

        aas.reset_ima_attestation()
        self.assertTrue(aas.check_quote_progress(10, 10))  # lag 0
        self.assertTrue(aas.check_quote_progress(0, 1))  # lag 1
        self.assertTrue(aas.check_quote_progress(1, 2))  # 1 progress, lag 1
        self.assertFalse(aas.check_quote_progress(0, 1))  # lag 1
        self.assertTrue(aas.check_quote_progress(2, 2))  # lag 0

        aas.reset_ima_attestation()
        self.assertTrue(aas.check_quote_progress(10, 12))  # lag 2
        self.assertFalse(aas.check_quote_progress(1, 2))  # lag 1; did not catch up
