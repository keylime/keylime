"""
Unit tests for tpm_main.mb_pcrs_to_check().

Tests the intersection of MEASUREDBOOT_PCRS with the active policy's
get_relevant_pcrs() set, which prevents false failures for PCRs extended
at runtime (e.g. PCR 11 by systemd-pcrphase).
"""

import unittest
from typing import FrozenSet
from unittest.mock import patch

# Importing example registers the "example" policy (and accept-all / reject-all
# are registered at module load time in policies.py itself).
import keylime.mba.elchecking.example  # noqa: F401 – side-effect import
from keylime.mba.elchecking import policies as mb_policies
from keylime.mba.elchecking import tests as mb_tests
from keylime.tpm.tpm_main import mb_pcrs_to_check

# A small, deterministic stand-in for config.MEASUREDBOOT_PCRS.
# Includes PCR 11 to exercise filtering of runtime-extended PCRs.
_TEST_MB_PCRS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 14]


class TestMbPcrsToCheck(unittest.TestCase):
    """Tests for mb_pcrs_to_check()."""

    def _run(self, policy_name: str) -> set[int]:
        with patch("keylime.tpm.tpm_main.config.MEASUREDBOOT_PCRS", _TEST_MB_PCRS):
            return mb_pcrs_to_check(policy_name)

    def test_accept_all_returns_full_set(self) -> None:
        """AcceptAll.get_relevant_pcrs() is empty → no filtering."""
        self.assertEqual(self._run("accept-all"), set(_TEST_MB_PCRS))

    def test_reject_all_returns_full_set(self) -> None:
        """RejectAll.get_relevant_pcrs() is empty → no filtering."""
        self.assertEqual(self._run("reject-all"), set(_TEST_MB_PCRS))

    def test_example_policy_excludes_pcr11(self) -> None:
        """Example policy only cares about PCRs 0-9 and 14; PCR 11 must be excluded."""
        result = self._run("example")
        self.assertNotIn(11, result, "PCR 11 should be excluded by the example policy")
        # All PCRs the example policy declares as relevant that are also in
        # _TEST_MB_PCRS must be present.
        example_policy = mb_policies.get_policy("example")
        assert example_policy is not None
        example_pcrs = example_policy.get_relevant_pcrs()
        self.assertEqual(result, set(_TEST_MB_PCRS) & example_pcrs)

    def test_unknown_policy_name_returns_full_set(self) -> None:
        """An unregistered policy name falls back to the full MEASUREDBOOT_PCRS."""
        self.assertEqual(self._run("no-such-policy"), set(_TEST_MB_PCRS))

    def test_custom_policy_with_single_pcr(self) -> None:
        """A policy that declares only PCR 0 as relevant limits the set to {0}."""

        class _SinglePCR(mb_policies.Policy):
            def get_relevant_pcrs(self) -> FrozenSet[int]:
                return frozenset({0})

            def refstate_to_test(self, refstate: mb_policies.RefState) -> mb_tests.Test:  # pragma: no cover
                raise NotImplementedError

        mb_policies.register("_test_single_pcr", _SinglePCR())
        try:
            result = self._run("_test_single_pcr")
            self.assertEqual(result, {0})
        finally:
            # Clean up the temporary test registration.
            mb_policies._registry.pop("_test_single_pcr", None)
