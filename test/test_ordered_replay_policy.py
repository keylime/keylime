"""Tests for the built-in ordered-replay measured-boot policy."""

import json
import types
import unittest
from typing import Any, Dict, List
from unittest.mock import patch

from keylime.common.algorithms import Hash
from keylime.failure import Component, Failure
from keylime.mba import mba
from keylime.mba.elchecking import elchecker, policies
from keylime.tpm.tpm_main import Tpm


def _fold(events: List[Dict[str, Any]], alg: str = "sha256") -> Dict[str, int]:
    """Model tpm2_eventlog's in-order replay for simple events (test helper only).

    Extends each event's digest into its PCR accumulator in list order, starting
    from the all-zero seed. This mirrors, for events with no special reset rules,
    the parser-calculated ``pcrs`` map the policy consumes. It is a test fixture,
    not the production replay, which lives in tpm2_eventlog.
    """
    hash_alg = Hash(alg)
    acc: Dict[int, bytes] = {}
    for event in events:
        if event.get("EventType") == "EV_NO_ACTION":
            continue
        pcr = event["PCRIndex"]
        for digest in event["Digests"]:
            if digest["AlgorithmId"] != alg:
                continue
            cur = acc.get(pcr, hash_alg.get_start_hash())
            acc[pcr] = hash_alg.hash(cur + bytes.fromhex(digest["Digest"]))
    return {str(pcr): int.from_bytes(value, byteorder="big") for pcr, value in acc.items()}


class TestOrderedReplayPolicy(unittest.TestCase):
    """The policy pins reference PCR values against the quote-bound parser map."""

    @staticmethod
    def _event(pcr: int, event_type: str, digest: bytes, algorithm: str = "sha256") -> Dict[str, Any]:
        return {
            "PCRIndex": pcr,
            "EventType": event_type,
            "Digests": [{"AlgorithmId": algorithm, "Digest": digest.hex()}],
        }

    def setUp(self) -> None:
        hash_alg = Hash.SHA256
        self.scrtm = hash_alg.hash(b"scrtm-version")
        self.firmware = hash_alg.hash(b"platform-firmware")
        self.bootloader = hash_alg.hash(b"bootloader")

        self.in_order = [
            self._event(0, "EV_S_CRTM_VERSION", self.scrtm),
            self._event(0, "EV_EFI_PLATFORM_FIRMWARE_BLOB", self.firmware),
            self._event(4, "EV_EFI_BOOT_SERVICES_APPLICATION", self.bootloader),
        ]
        # The parser-calculated PCR map that the verifier binds to the quote.
        self.log_pcrs = {"sha256": _fold(self.in_order)}
        self.measurement_data = {"events": self.in_order, "pcrs": self.log_pcrs}
        self.refstate = {"pcrs": {"sha256": dict(self.log_pcrs["sha256"])}}

    @staticmethod
    def _failure_ids(failure: Failure) -> List[str]:
        return failure.get_event_ids()

    def _bootlog_evaluate(
        self,
        refstate: Dict[str, Any],
        measurement_data: Dict[str, Any],
        bound_pcrs: set,
        quote_hash_alg: str,
    ) -> Failure:
        with patch("keylime.mba.elchecking.elchecker.config.get", return_value="ordered-replay"):
            return elchecker.bootlog_evaluate(
                json.dumps(refstate),
                measurement_data,
                bound_pcrs,
                "test-agent",
                quote_hash_alg=quote_hash_alg,
                log_bound_pcrs=bound_pcrs,
            )

    # --- policy-level value matching -------------------------------------------------

    def test_accepts_matching_reference(self) -> None:
        reason = policies.evaluate("ordered-replay", self.refstate, self.measurement_data)
        self.assertEqual(reason, "")

    def test_accepts_full_size_hex_reference(self) -> None:
        pcr0 = self.log_pcrs["sha256"]["0"].to_bytes(32, "big")
        pcr4 = self.log_pcrs["sha256"]["4"].to_bytes(32, "big")
        refstate = {"pcrs": {"sha256": {"0": "0x" + pcr0.hex(), "4": pcr4.hex()}}}
        reason = policies.evaluate("ordered-replay", refstate, self.measurement_data)
        self.assertEqual(reason, "")

    def test_rejects_wrong_reference_value(self) -> None:
        refstate = {"pcrs": {"sha256": {"0": "00" * 32}}}
        reason = policies.evaluate("ordered-replay", refstate, self.measurement_data)
        self.assertIn("sha256 PCR 0 is", reason)

    def test_rejects_pcr_absent_from_parser_map(self) -> None:
        refstate = {"pcrs": {"sha256": {"5": "00" * 32}}}
        reason = policies.evaluate("ordered-replay", refstate, self.measurement_data)
        self.assertIn("PCR 5 is absent", reason)

    def test_rejects_bank_absent_from_parser_map(self) -> None:
        measurement_data = {"events": self.in_order, "pcrs": {}}
        reason = policies.evaluate("ordered-replay", self.refstate, measurement_data)
        self.assertIn("no sha256 pcrs", reason)

    def test_rejects_unauthenticatable_bank(self) -> None:
        refstate = {"pcrs": {"sm3_256": {"0": "00" * 32}}}
        with self.assertRaises(Exception) as ctx:
            policies.evaluate("ordered-replay", refstate, self.measurement_data)
        self.assertIn("cannot be authenticated by a quote", str(ctx.exception))

    # --- issue #1: parser handles StartupLocality, the policy honors it --------------

    def test_locality_is_not_collapsed(self) -> None:
        hash_alg = Hash.SHA256
        digest = hash_alg.hash(b"crtm")
        # PCR 0 seeded for locality 3 (last byte 0x03), as tpm2_eventlog reports it.
        loc3_seed = b"\x00" * 31 + b"\x03"
        loc3_pcr0 = hash_alg.hash(loc3_seed + digest)
        loc0_pcr0 = hash_alg.hash(hash_alg.get_start_hash() + digest)
        self.assertNotEqual(loc3_pcr0, loc0_pcr0)

        measurement_data = {"events": [], "pcrs": {"sha256": {"0": int.from_bytes(loc3_pcr0, "big")}}}
        # A locality-0 reference must not match a locality-3 boot.
        loc0_ref = {"pcrs": {"sha256": {"0": int.from_bytes(loc0_pcr0, "big")}}}
        self.assertIn("PCR 0 is", policies.evaluate("ordered-replay", loc0_ref, measurement_data))
        # The correct locality-3 reference matches.
        loc3_ref = {"pcrs": {"sha256": {"0": int.from_bytes(loc3_pcr0, "big")}}}
        self.assertEqual(policies.evaluate("ordered-replay", loc3_ref, measurement_data), "")

    # --- issue #3: per-PCR ordering, not cross-PCR interleaving ----------------------

    def test_same_pcr_reorder_rejected_cross_pcr_reorder_accepted(self) -> None:
        # Reference pins the in-order state.
        refstate = self.refstate

        # Cross-PCR permutation: move the PCR 4 event ahead of the PCR 0 events,
        # keeping each PCR's internal order. The per-PCR endpoints are unchanged,
        # so the parser map is identical and the reference still matches.
        cross_pcr = [self.in_order[2], self.in_order[0], self.in_order[1]]
        cross_data = {"events": cross_pcr, "pcrs": {"sha256": _fold(cross_pcr)}}
        self.assertEqual(cross_data["pcrs"], self.log_pcrs)
        self.assertEqual(policies.evaluate("ordered-replay", refstate, cross_data), "")

        # Same-PCR permutation: swap the two PCR 0 events. PCR 0's value changes,
        # so the reference no longer matches.
        same_pcr = [self.in_order[1], self.in_order[0], self.in_order[2]]
        same_data = {"events": same_pcr, "pcrs": {"sha256": _fold(same_pcr)}}
        self.assertNotEqual(same_data["pcrs"]["sha256"]["0"], self.log_pcrs["sha256"]["0"])
        self.assertIn("sha256 PCR 0 is", policies.evaluate("ordered-replay", refstate, same_data))

    # --- quote-context binding through elchecker.bootlog_evaluate --------------------

    def test_bootlog_evaluate_accepts_bound_bank_and_pcrs(self) -> None:
        failure = self._bootlog_evaluate(self.refstate, self.measurement_data, {0, 4}, "sha256")
        self.assertFalse(failure)

    def test_bootlog_evaluate_reports_unbound_pcr_as_missing_pcrs(self) -> None:
        hash_alg = Hash.SHA256
        digest = hash_alg.hash(b"late-boot-event")
        events = [self._event(5, "EV_ACTION", digest)]
        measurement_data = {"events": events, "pcrs": {"sha256": _fold(events)}}
        refstate = {"pcrs": {"sha256": {"5": measurement_data["pcrs"]["sha256"]["5"]}}}
        failure = self._bootlog_evaluate(refstate, measurement_data, {0}, "sha256")
        self.assertIn("measured_boot.missing_pcrs", self._failure_ids(failure))
        self.assertIn("5", failure.events[0].context)

    def test_bootlog_evaluate_rejects_wrong_quote_bank(self) -> None:
        failure = self._bootlog_evaluate(self.refstate, self.measurement_data, {0, 4}, "sha384")
        self.assertIn("measured_boot.quote_context", self._failure_ids(failure))
        self.assertIn("do not match quoted bank sha384", failure.events[0].context)

    def test_bootlog_evaluate_rejects_missing_quote_bank(self) -> None:
        with patch("keylime.mba.elchecking.elchecker.config.get", return_value="ordered-replay"):
            failure = elchecker.bootlog_evaluate(
                json.dumps(self.refstate), self.measurement_data, {0, 4}, "test-agent", log_bound_pcrs={0, 4}
            )
        self.assertIn("measured_boot.quote_context", self._failure_ids(failure))
        self.assertIn("quote hash algorithm is unavailable", failure.events[0].context)

    def test_bootlog_evaluate_rejects_missing_log_bound_pcrs(self) -> None:
        # ordered-replay needs the quote-bound PCR set; omitting it must not fall back
        # to the broad quote-PCR set.
        with patch("keylime.mba.elchecking.elchecker.config.get", return_value="ordered-replay"):
            failure = elchecker.bootlog_evaluate(
                json.dumps(self.refstate), self.measurement_data, {0, 4}, "test-agent", quote_hash_alg="sha256"
            )
        self.assertIn("measured_boot.quote_context", self._failure_ids(failure))
        self.assertIn("quote-bound PCRs was not provided", failure.events[0].context)

    def test_bootlog_evaluate_rejects_multiple_reference_banks(self) -> None:
        sha384 = Hash.SHA384
        pcr0 = sha384.hash(sha384.get_start_hash() + sha384.hash(b"scrtm-version"))
        refstate = {
            "pcrs": {
                "sha256": self.refstate["pcrs"]["sha256"],
                "sha384": {"0": int.from_bytes(pcr0, byteorder="big")},
            }
        }
        failure = self._bootlog_evaluate(refstate, self.measurement_data, {0, 4}, "sha256")
        self.assertIn("measured_boot.quote_context", self._failure_ids(failure))
        self.assertIn("reference PCR banks", failure.events[0].context)

    # --- issue #2: an empty reference state must not disable the policy ---------------

    def test_bootlog_evaluate_rejects_empty_ordered_replay_refstate(self) -> None:
        with patch("keylime.mba.elchecking.elchecker.config.get", return_value="ordered-replay"):
            failure = elchecker.bootlog_evaluate(
                "{}", self.measurement_data, {0, 4}, "test-agent", quote_hash_alg="sha256"
            )
        self.assertIn("measured_boot.invalid_mb_policy", self._failure_ids(failure))

    def test_bootlog_evaluate_rejects_none_refstate(self) -> None:
        with patch("keylime.mba.elchecking.elchecker.config.get", return_value="ordered-replay"):
            failure = elchecker.bootlog_evaluate(
                None, self.measurement_data, {0, 4}, "test-agent", quote_hash_alg="sha256"
            )
        self.assertIn("measured_boot.invalid_mb_policy", self._failure_ids(failure))

    def test_bootlog_evaluate_rejects_empty_string_refstate(self) -> None:
        with patch("keylime.mba.elchecking.elchecker.config.get", return_value="ordered-replay"):
            failure = elchecker.bootlog_evaluate(
                "", self.measurement_data, {0, 4}, "test-agent", quote_hash_alg="sha256"
            )
        self.assertIn("measured_boot.invalid_mb_policy", self._failure_ids(failure))

    def test_bootlog_evaluate_reports_malformed_json_without_raising(self) -> None:
        for bad in ("{", "not JSON", "   "):
            with self.subTest(refstate=bad):
                with patch("keylime.mba.elchecking.elchecker.config.get", return_value="ordered-replay"):
                    failure = elchecker.bootlog_evaluate(
                        bad, self.measurement_data, {0, 4}, "test-agent", quote_hash_alg="sha256", log_bound_pcrs={0, 4}
                    )
                self.assertIn("measured_boot.invalid_mb_policy", self._failure_ids(failure))

    def test_bootlog_evaluate_accepts_empty_accept_all_refstate(self) -> None:
        with patch("keylime.mba.elchecking.elchecker.config.get", return_value="accept-all"):
            failure = elchecker.bootlog_evaluate(
                "{}", self.measurement_data, set(), "test-agent", quote_hash_alg="sha256"
            )
        self.assertFalse(failure)

    def test_elchecker_runs_custom_every_quote_policy_on_empty_refstate(self) -> None:
        # A custom policy that accepts an empty reference state but requires
        # every-quote evaluation must actually run its test through the real
        # evaluator, not be short-circuited by the empty-state check.
        class EveryQuoteRuns(policies.Policy):
            def get_relevant_pcrs(self) -> frozenset:
                return frozenset()

            def requires_evaluation_every_quote(self) -> bool:
                return True

            def refstate_to_test(self, refstate: Any) -> Any:
                return policies.tests.RejectAll("custom policy ran")

        policies.register("every-quote-runs", EveryQuoteRuns())
        try:
            with patch("keylime.mba.elchecking.elchecker.config.get", return_value="every-quote-runs"):
                failure = elchecker.bootlog_evaluate(
                    "{}", self.measurement_data, {0, 4}, "test-agent", quote_hash_alg="sha256", log_bound_pcrs={0, 4}
                )
        finally:
            policies.unregister("every-quote-runs")
        self.assertIn("measured_boot.policy_every-quote-runs", self._failure_ids(failure))
        self.assertIn("custom policy ran", failure.events[0].context)

    def test_elchecker_enforces_log_bound_for_custom_empty_state_policy(self) -> None:
        # A custom policy that accepts an empty reference state but requires the
        # log-bound PCR set must reach the check and reject when that set is omitted,
        # rather than being skipped before its requirement is enforced.
        class LogBoundRuns(policies.Policy):
            def get_relevant_pcrs(self) -> frozenset:
                return frozenset()

            def requires_log_bound_pcrs(self) -> bool:
                return True

            def refstate_to_test(self, refstate: Any) -> Any:
                return policies.tests.AcceptAll()

        policies.register("log-bound-runs", LogBoundRuns())
        try:
            with patch("keylime.mba.elchecking.elchecker.config.get", return_value="log-bound-runs"):
                failure = elchecker.bootlog_evaluate(
                    "{}", self.measurement_data, {0, 4}, "test-agent", quote_hash_alg="sha256"
                )
        finally:
            policies.unregister("log-bound-runs")
        self.assertIn("measured_boot.quote_context", self._failure_ids(failure))
        self.assertIn("quote-bound PCRs was not provided", failure.events[0].context)

    def test_check_pcrs_runs_ordered_replay_on_empty_refstate(self) -> None:
        parser_failure = Failure(Component.MEASURED_BOOT)
        with (
            patch(
                "keylime.tpm.tpm_main.mba.bootlog_parse",
                return_value=({}, None, self.measurement_data, parser_failure),
            ),
            patch("keylime.tpm.tpm_main.mba.policy_is_valid", return_value=True),
            patch("keylime.tpm.tpm_main.config.get", return_value="once"),
            patch(
                "keylime.tpm.tpm_main.mba.bootlog_evaluate",
                return_value=Failure(Component.MEASURED_BOOT),
            ) as evaluate,
        ):
            Tpm().check_pcrs(
                agentAttestState=None,
                tpm_policy={},
                pcrs_dict={},
                data=None,
                ima_measurement_list=None,
                runtime_policy=None,
                ima_keyrings=None,
                mb_measurement_list="boot-log",
                mb_policy="{}",
                hash_alg=Hash.SHA256,
                count=0,
                mb_policy_name="ordered-replay",
            )
        # ordered-replay requires content, so evaluation still runs for an empty {}.
        evaluate.assert_called_once()

    def _check_pcrs_evaluate_mock(
        self, mb_policy: Any, count: int, mb_evaluate: str = "once", mb_policy_name: str = "ordered-replay"
    ) -> Any:
        parser_failure = Failure(Component.MEASURED_BOOT)
        with (
            patch(
                "keylime.tpm.tpm_main.mba.bootlog_parse",
                return_value=({}, None, self.measurement_data, parser_failure),
            ),
            patch("keylime.tpm.tpm_main.mba.policy_is_valid", return_value=True),
            patch("keylime.tpm.tpm_main.config.get", return_value=mb_evaluate),
            patch(
                "keylime.tpm.tpm_main.mba.bootlog_evaluate",
                return_value=Failure(Component.MEASURED_BOOT),
            ) as evaluate,
        ):
            Tpm().check_pcrs(
                agentAttestState=None,
                tpm_policy={},
                pcrs_dict={},
                data=None,
                ima_measurement_list=None,
                runtime_policy=None,
                ima_keyrings=None,
                mb_measurement_list="boot-log",
                mb_policy=mb_policy,
                hash_alg=Hash.SHA256,
                count=count,
                mb_policy_name=mb_policy_name,
            )
        return evaluate

    def test_check_pcrs_evaluates_ordered_replay_in_one_shot(self) -> None:
        # One-shot verification uses count == -1; 'once' would otherwise skip it.
        self._check_pcrs_evaluate_mock("{}", count=-1).assert_called_once()

    def test_check_pcrs_evaluates_ordered_replay_on_later_attestation(self) -> None:
        # A later quote (count > 0) is still pinned to the reference state.
        self._check_pcrs_evaluate_mock("{}", count=5).assert_called_once()

    def test_check_pcrs_evaluates_ordered_replay_with_none_mb_policy(self) -> None:
        self._check_pcrs_evaluate_mock(None, count=0).assert_called_once()

    def test_check_pcrs_evaluates_ordered_replay_with_empty_string_mb_policy(self) -> None:
        self._check_pcrs_evaluate_mock("", count=0).assert_called_once()

    def test_check_pcrs_runs_every_quote_policy_that_accepts_empty_refstate(self) -> None:
        # A custom policy that accepts an empty reference state but needs to run on
        # every quote must not be skipped once (count > 0).
        class EveryQuoteEmptyOk(policies.Policy):
            def get_relevant_pcrs(self) -> frozenset:
                return frozenset()

            def requires_evaluation_every_quote(self) -> bool:
                return True

            def refstate_to_test(self, refstate: Any) -> Any:
                return policies.tests.AcceptAll()

        policies.register("every-quote-empty-ok", EveryQuoteEmptyOk())
        try:
            evaluate = self._check_pcrs_evaluate_mock("{}", count=5, mb_policy_name="every-quote-empty-ok")
            evaluate.assert_called_once()
        finally:
            policies.unregister("every-quote-empty-ok")

    def test_check_pcrs_reports_malformed_refstate_without_raising(self) -> None:
        # A malformed non-empty reference string is an operator error: it is flagged
        # as invalid_mb_policy and the evaluator is not invoked.
        parser_failure = Failure(Component.MEASURED_BOOT)
        with (
            patch(
                "keylime.tpm.tpm_main.mba.bootlog_parse",
                return_value=({}, None, self.measurement_data, parser_failure),
            ),
            patch("keylime.tpm.tpm_main.mba.policy_is_valid", side_effect=elchecker.policy_is_valid),
            patch("keylime.tpm.tpm_main.config.get", return_value="once"),
            patch("keylime.tpm.tpm_main.mba.bootlog_evaluate") as evaluate,
        ):
            failure = Tpm().check_pcrs(
                agentAttestState=None,
                tpm_policy={},
                pcrs_dict={},
                data=None,
                ima_measurement_list=None,
                runtime_policy=None,
                ima_keyrings=None,
                mb_measurement_list="boot-log",
                mb_policy="{",
                hash_alg=Hash.SHA256,
                count=0,
                mb_policy_name="ordered-replay",
            )
        evaluate.assert_not_called()
        self.assertTrue(any("invalid_mb_policy" in event_id for event_id in self._failure_ids(failure)))

    def test_check_pcrs_fails_closed_on_unknown_policy_name(self) -> None:
        # A misspelled or unregistered configured policy name must fail closed even
        # when the reference state is missing or empty, not skip evaluation.
        for refstate in (None, "", "{}"):
            with self.subTest(refstate=refstate):
                parser_failure = Failure(Component.MEASURED_BOOT)
                with (
                    patch(
                        "keylime.tpm.tpm_main.mba.bootlog_parse",
                        return_value=({}, None, self.measurement_data, parser_failure),
                    ),
                    patch("keylime.tpm.tpm_main.config.get", return_value="once"),
                    patch("keylime.tpm.tpm_main.mba.bootlog_evaluate") as evaluate,
                ):
                    failure = Tpm().check_pcrs(
                        agentAttestState=None,
                        tpm_policy={},
                        pcrs_dict={},
                        data=None,
                        ima_measurement_list=None,
                        runtime_policy=None,
                        ima_keyrings=None,
                        mb_measurement_list="boot-log",
                        mb_policy=refstate,
                        hash_alg=Hash.SHA256,
                        count=0,
                        mb_policy_name="ordered-repay",
                    )
                evaluate.assert_not_called()
                self.assertTrue(failure)
                self.assertTrue(any("invalid_mb_policy" in event_id for event_id in self._failure_ids(failure)))

    # --- issue #4: legacy PCR-set semantics and the failure-id split -----------------

    def test_check_pcrs_passes_broad_and_log_bound_pcr_sets(self) -> None:
        measurement_data = {"events": self.in_order, "pcrs": self.log_pcrs}
        parser_failure = Failure(Component.MEASURED_BOOT)
        mb_policy = json.dumps({"pcrs": {"sha256": {"0": self.log_pcrs["sha256"]["0"]}}})
        quote_only_pcr = "ab" * 32

        with (
            patch(
                "keylime.tpm.tpm_main.mba.bootlog_parse",
                return_value=({"0": self.log_pcrs["sha256"]["0"]}, None, measurement_data, parser_failure),
            ),
            patch("keylime.tpm.tpm_main.mba.policy_is_valid", return_value=True),
            patch("keylime.tpm.tpm_main.config.get", return_value="always"),
            patch(
                "keylime.tpm.tpm_main.mba.bootlog_evaluate",
                return_value=Failure(Component.MEASURED_BOOT),
            ) as evaluate,
        ):
            failure = Tpm().check_pcrs(
                agentAttestState=None,
                tpm_policy={"23": [quote_only_pcr]},
                pcrs_dict={0: hex(self.log_pcrs["sha256"]["0"])[2:], 23: quote_only_pcr},
                data=None,
                ima_measurement_list=None,
                runtime_policy=None,
                ima_keyrings=None,
                mb_measurement_list="boot-log",
                mb_policy=mb_policy,
                hash_alg=Hash.SHA256,
                count=0,
                mb_policy_name="ordered-replay",
            )

        self.assertFalse(failure)
        # The broad quote set (PCR 0 plus the allowlisted PCR 23) is passed
        # positionally for legacy implementations; the log-bound set {0} is passed
        # as the keyword the new implementation reads.
        evaluate.assert_called_once_with(
            mb_policy,
            measurement_data,
            {0, 23},
            "<unknown>",
            quote_hash_alg="sha256",
            log_bound_pcrs={0},
        )

    def test_mba_frontend_gives_legacy_implementation_the_broad_pcr_set(self) -> None:
        expected = Failure(Component.MEASURED_BOOT)

        def legacy_evaluate(policy: str, measurement: object, pcrs: set, agent: str) -> Failure:
            # Legacy implementations keep the original pcrsInQuote, not log_bound_pcrs.
            self.assertEqual((policy, measurement, pcrs, agent), ("{}", {}, {0, 23}, "test-agent"))
            return expected

        implementation = types.SimpleNamespace(bootlog_evaluate=legacy_evaluate)
        with patch("keylime.mba.mba._find_implementation", return_value=implementation):
            result = mba.bootlog_evaluate("{}", {}, {0, 23}, "test-agent", quote_hash_alg="sha256", log_bound_pcrs={0})
        self.assertIs(result, expected)

    def test_mba_frontend_gives_kwargs_implementation_the_broad_pcr_set(self) -> None:
        # An implementation that accepts **kwargs keeps the broad pcrsInQuote
        # positionally and receives the extra context by keyword.
        expected = Failure(Component.MEASURED_BOOT)
        captured: Dict[str, Any] = {}

        def kwargs_evaluate(policy: str, measurement: object, pcrs: set, agent: str, **kwargs: Any) -> Failure:
            captured["positional"] = (policy, measurement, pcrs, agent)
            captured["kwargs"] = kwargs
            return expected

        implementation = types.SimpleNamespace(bootlog_evaluate=kwargs_evaluate)
        with patch("keylime.mba.mba._find_implementation", return_value=implementation):
            result = mba.bootlog_evaluate("{}", {}, {0, 23}, "test-agent", quote_hash_alg="sha256", log_bound_pcrs={0})
        self.assertIs(result, expected)
        self.assertEqual(captured["positional"], ("{}", {}, {0, 23}, "test-agent"))
        self.assertEqual(captured["kwargs"], {"quote_hash_alg": "sha256", "log_bound_pcrs": {0}})

    # --- PCR-boundary restriction ----------------------------------------------------

    def test_refstate_cannot_expand_measured_boot_pcr_boundary(self) -> None:
        refstate = {"pcrs": {"sha256": {"23": "00" * 32}}}
        self.assertEqual(Tpm.mb_pcrs_to_check("ordered-replay", refstate), set())


if __name__ == "__main__":
    unittest.main()
