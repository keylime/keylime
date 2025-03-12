import unittest

from keylime import agentstates
from keylime.common.algorithms import Hash


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


class TestTPMState(unittest.TestCase):
    def test_initial_pcr_value(self):
        tpm_state = agentstates.TPMState()
        test_hash = Hash.SHA1
        # check that the initial value is correct for few different PCRs
        self.assertEqual(tpm_state.initial_pcr_value(0, test_hash), test_hash.get_start_hash())
        self.assertEqual(tpm_state.initial_pcr_value(2, test_hash), test_hash.get_start_hash())
        self.assertEqual(tpm_state.initial_pcr_value(16, test_hash), test_hash.get_start_hash())
        self.assertEqual(tpm_state.initial_pcr_value(17, test_hash), test_hash.get_ff_hash())
        self.assertEqual(tpm_state.initial_pcr_value(18, test_hash), test_hash.get_ff_hash())
        self.assertEqual(tpm_state.initial_pcr_value(23, test_hash), test_hash.get_ff_hash())

    def test_init_pcr(self):
        tpm_state = agentstates.TPMState()
        test_hash = Hash.SHA1

        # check that we can init start hash PCRs
        self.assertIsNone(tpm_state.get_pcr(0))
        tpm_state.init_pcr(0, test_hash)
        self.assertEqual(tpm_state.get_pcr(0), test_hash.get_start_hash())

        # check that it didn't init other PCRs
        self.assertIsNone(tpm_state.get_pcr(1))

        # check another start hash one
        self.assertIsNone(tpm_state.get_pcr(16))
        tpm_state.init_pcr(16, test_hash)
        self.assertEqual(tpm_state.get_pcr(16), test_hash.get_start_hash())

        # now check a couple of FF hash ones
        self.assertIsNone(tpm_state.get_pcr(17))
        tpm_state.init_pcr(17, test_hash)
        self.assertEqual(tpm_state.get_pcr(17), test_hash.get_ff_hash())

        self.assertIsNone(tpm_state.get_pcr(23))
        tpm_state.init_pcr(23, test_hash)
        self.assertEqual(tpm_state.get_pcr(23), test_hash.get_ff_hash())
