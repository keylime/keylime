"""Unit tests for the claims pipeline contracts and failure normalization."""

import copy
import json
import unittest
from typing import Any

from keylime.claims.base import (
    EvaluatedEvidence,
    EvaluationResult,
    FailureEntry,
    RenderedResponse,
    VerificationOutput,
)
from keylime.claims.failures import (
    MAX_FAILURE_ENTRIES,
    MAX_FIELD_LEN,
    normalize_failure,
)
from keylime.failure import Component, Failure


def _make_failure_event(component: Component, event_id: str, context, recoverable: bool = True) -> Failure:
    failure = Failure(component)
    failure.add_event(event_id, context, recoverable)
    return failure


def _make_result(**overrides) -> EvaluationResult:
    defaults = {
        "evaluation_id": "default",
        "evidence_id": "default",
        "evidence_type": "tpm",
        "status": "pass",
        "claims": {"pcrs": {}},
        "failures": [],
        "policy": "tpm:inline",
        "policy_source": "inline",
    }
    defaults.update(overrides)
    return EvaluationResult(**defaults)


class ContractsTest(unittest.TestCase):
    def test_forward_compatible_fields_default_to_none(self) -> None:
        result = _make_result()
        self.assertIsNone(result.policy_uuid)
        self.assertIsNone(result.policy_revision)
        self.assertIsNone(result.resolved_sub_policies)
        self.assertIsNone(result.trustworthiness)
        self.assertIsNone(result.trust_anchor_fingerprints)
        self.assertIsNone(result.evidence_nonce)

    def test_frozen_dataclasses_reject_mutation(self) -> None:
        result = _make_result()
        with self.assertRaises(Exception):
            result.status = "fail"  # type: ignore[misc]

        evidence = EvaluatedEvidence(
            evaluation_id="default",
            evidence_id="default",
            evidence_type="tpm",
            evidence={},
            policies={},
            policy_name="tpm:inline",
            policy_source="inline",
            failure=None,
            status="pass",
        )
        with self.assertRaises(Exception):
            evidence.status = "error"  # type: ignore[misc]

        entry = FailureEntry(type="tpm.quote_invalid", message="msg")
        with self.assertRaises(Exception):
            entry.message = "other"  # type: ignore[misc]

    def test_verification_output_token_defaults_none_and_is_mutable(self) -> None:
        output = VerificationOutput(results=[], ear_claims=None)
        self.assertIsNone(output.ear_token)
        output.ear_token = "signed-token"
        self.assertEqual(output.ear_token, "signed-token")

    def test_rendered_response_status_defaults_none(self) -> None:
        # Forward-compatible field: None means "derive the HTTP status
        # from the body"; the error path will set it (4xx/5xx for a
        # Problem Details document) before the web layer lands.
        response = RenderedResponse(content_type="application/eat+jwt", body="token")
        self.assertIsNone(response.status)

    def test_evaluation_result_is_intentionally_unhashable(self) -> None:
        result = _make_result()
        with self.assertRaises(TypeError):
            hash(result)


class NormalizeFailureBasicTest(unittest.TestCase):
    def test_empty_failure_yields_empty_list(self) -> None:
        self.assertEqual(normalize_failure(Failure(Component.DEFAULT)), [])
        self.assertEqual(normalize_failure(None), [])

    def test_dict_context_message_popped(self) -> None:
        failure = _make_failure_event(
            Component.IMA, "not_in_allowlist", {"message": "file not in allowlist", "path": "/usr/bin/evil"}
        )
        entries = normalize_failure(failure)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].type, "tpm.ima_violation")
        self.assertEqual(entries[0].message, "file not in allowlist")
        self.assertEqual(entries[0].context, {"path": "/usr/bin/evil"})

    def test_context_without_message_falls_back_to_type(self) -> None:
        failure = _make_failure_event(Component.PCR_VALIDATION, "invalid_pcr_10", {"expected": "aa", "got": "bb"})
        entries = normalize_failure(failure)
        self.assertEqual(entries[0].message, "tpm.pcr_mismatch")
        self.assertEqual(entries[0].context, {"expected": "aa", "got": "bb"})

    def test_string_context_wraps_message(self) -> None:
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", "signature mismatch")
        entries = normalize_failure(failure)
        self.assertEqual(entries[0].message, "signature mismatch")
        self.assertIsNone(entries[0].context)

    def test_unparsable_json_context_becomes_none(self) -> None:
        # The public Event API always json.dumps a dict, so an unparsable
        # context cannot occur naturally — construct it by overwriting the
        # attribute directly. The defensive branch must stay.
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"message": "m"})
        failure.events[0].context = "<<<not json>>>"
        entries = normalize_failure(failure)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].type, "tpm.quote_invalid")
        self.assertIsNone(entries[0].context)

    def test_deeply_nested_json_string_context_dropped(self) -> None:
        # json.loads recurses over the parsed structure: a nesting depth
        # beyond the interpreter limit must degrade like an unparsable
        # context, not abort the whole batch with RecursionError.
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"message": "m"})
        failure.events[0].context = "[" * 5000 + "]" * 5000
        with self.assertLogs("keylime.claims.failures", level="WARNING"):
            entries = normalize_failure(failure)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].type, "tpm.quote_invalid")
        self.assertIsNone(entries[0].context)

    def test_deeply_nested_dict_context_dropped_message_kept(self) -> None:
        deep: Any = {}
        for _ in range(5000):
            deep = {"n": deep}
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"message": "m"})
        failure.events[0].context = json.dumps({"message": "signature mismatch", "detail": deep})
        with self.assertLogs("keylime.claims.failures", level="WARNING"):
            entries = normalize_failure(failure)
        self.assertEqual(entries[0].message, "signature mismatch")
        self.assertIsNone(entries[0].context)

    def test_non_object_json_context_dropped_with_log(self) -> None:
        # Valid JSON that is not an object carries no message and no
        # structured detail — dropped, and (like every other drop path)
        # loudly.
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"message": "m"})
        failure.events[0].context = '["a", "b"]'
        with self.assertLogs("keylime.claims.failures", level="WARNING") as captured:
            entries = normalize_failure(failure)
        self.assertEqual(entries[0].context, None)
        self.assertTrue(any("not a JSON object" in line for line in captured.output))

    def test_empty_remainder_context_becomes_none(self) -> None:
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"message": "only a message"})
        entries = normalize_failure(failure)
        self.assertIsNone(entries[0].context)


class NormalizeFailureMappingTest(unittest.TestCase):
    def test_known_pairs_map_to_external_types(self) -> None:
        cases = [
            (Component.IMA, ["validation", "ima-ng"], "not_in_allowlist", "tpm.ima_violation"),
            (Component.PCR_VALIDATION, None, "invalid_pcr_10", "tpm.pcr_mismatch"),
            (Component.PCR_VALIDATION, None, "unused_pcr_10", "tpm.pcr_mismatch"),
            (Component.DEFAULT, None, "missing_param", "eval.missing_param"),
            (Component.DEFAULT, None, "missing_policy", "eval.missing_policy"),
            (Component.QUOTE_VALIDATION, None, "invalid_hash_alg", "eval.invalid_hash_alg"),
            (Component.QUOTE_VALIDATION, None, "quote_validation", "tpm.quote_invalid"),
            (Component.MEASURED_BOOT, None, "bad_pcr", "tpm.mb_mismatch"),
            (Component.INTERNAL, None, "anything", "eval.internal_error"),
        ]
        for component, sub_components, event_id, expected in cases:
            with self.subTest(event_id=event_id):
                failure = Failure(component, sub_components)
                failure.add_event(event_id, {"message": "m"}, True)
                entries = normalize_failure(failure)
                self.assertEqual(entries[0].type, expected)

    def test_snp_namespace_derived_from_evidence_type(self) -> None:
        # The generic TEE component claims no flavor by itself; the
        # namespace comes from the coarse evidence type ("tee-snp" -> snp),
        # matching the plan's taxonomy.
        failure = _make_failure_event(Component.TEE, "vcek_fetch", {"message": "could not fetch VCEK"})
        entries = normalize_failure(failure, "tee-snp")
        self.assertEqual(entries[0].type, "snp.vcek_fetch")

    def test_tee_namespace_derived_for_future_flavors(self) -> None:
        # "tee-tdx" -> "tdx" by rule: future flavors need no new mapping.
        failure = _make_failure_event(Component.TEE, "measurement_mismatch", {"message": "m"})
        entries = normalize_failure(failure, "tee-tdx")
        self.assertEqual(entries[0].type, "tdx.measurement_mismatch")

    def test_tee_event_without_evidence_type_claims_no_flavor(self) -> None:
        failure = _make_failure_event(Component.TEE, "vcek_fetch", {"message": "could not fetch VCEK"})
        entries = normalize_failure(failure)
        self.assertEqual(entries[0].type, "tee.vcek_fetch")

    def test_invalid_tee_evidence_type_claims_no_flavor(self) -> None:
        # A flavor that fails the identifier guard must never be
        # substituted into a type field inside the signed token.
        failure = _make_failure_event(Component.TEE, "vcek_fetch", {"message": "m"})
        entries = normalize_failure(failure, "tee-Bad Type!")
        self.assertEqual(entries[0].type, "tee.vcek_fetch")

    def test_snp_event_without_sub_event_maps_to_unmapped(self) -> None:
        # An event id with no sub-event (empty remainder after the
        # component) must NOT produce a malformed "snp." template type in
        # the signed output — it degrades to the closed unmapped type.
        failure = Failure(Component.TEE)
        failure.add_event("", {"message": "m"}, True)
        self.assertEqual(failure.get_event_ids(), ["tee_attestation."])
        with self.assertLogs("keylime.claims.failures", level="WARNING"):
            entries = normalize_failure(failure, "tee-snp")
        self.assertEqual(entries[0].type, "eval.unmapped_failure")
        self.assertNotEqual(entries[0].type, "snp.")

    def test_longest_match_wins(self) -> None:
        # "invalid_pcr_10" matches both "invalid_pcr_*" (specific) and the
        # component would have no wildcard — but for QUOTE_VALIDATION,
        # "invalid_hash_alg" (exact) must beat "*".
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "invalid_hash_alg", {"message": "m"})
        self.assertEqual(normalize_failure(failure)[0].type, "eval.invalid_hash_alg")

    def test_sub_component_prefix_participates(self) -> None:
        # Real IMA ids are "ima.validation.ima-ng.not_in_allowlist": the
        # remainder after the component is "validation.ima-ng.not_in_allowlist".
        failure = Failure(Component.IMA, ["validation", "ima-ng"])
        failure.add_event("not_in_allowlist", {"message": "m"}, True)
        entries = normalize_failure(failure)
        self.assertEqual(entries[0].type, "tpm.ima_violation")

    def test_unmapped_pair_yields_closed_type_and_logs(self) -> None:
        failure = _make_failure_event(Component.DEFAULT, "brand_new_event", {"message": "m"})
        with self.assertLogs("keylime.claims.failures", level="WARNING") as captured:
            entries = normalize_failure(failure)
        self.assertEqual(entries[0].type, "eval.unmapped_failure")
        # The internal id is logged, never emitted into the entry.
        self.assertNotIn("default.brand_new_event", json.dumps([e.__dict__ for e in entries]))
        self.assertTrue(any("default.brand_new_event" in line for line in captured.output))


class NormalizeFailureBoundsTest(unittest.TestCase):
    def test_more_than_max_events_truncates(self) -> None:
        failure = Failure(Component.IMA)
        for _ in range(MAX_FAILURE_ENTRIES + 50):
            failure.add_event("not_in_allowlist", {"message": "m"}, True)
        entries = normalize_failure(failure)
        self.assertEqual(len(entries), MAX_FAILURE_ENTRIES)
        self.assertEqual(entries[-1].type, "eval.truncated")
        self.assertEqual(entries[-1].context, {"omitted": 51})

    def test_long_string_fields_truncated(self) -> None:
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"message": "x" * 5000})
        entries = normalize_failure(failure)
        self.assertEqual(len(entries[0].message), MAX_FIELD_LEN)

    def test_large_nested_context_dropped(self) -> None:
        # A single event whose context contains a ~100 KB list must have
        # its context dropped entirely (serialized-size budget).
        big_list = list(range(15000))
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"data": big_list})
        entries = normalize_failure(failure)
        self.assertEqual(len(entries), 1)
        self.assertIsNone(entries[0].context)

    def test_multibyte_context_measured_in_bytes(self) -> None:
        # 700 euro signs survive the per-field character cap (1024) but
        # expand to ~4200 ASCII escape characters when serialized — over
        # the 4096-byte budget — so the context must be dropped.
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"data": "€" * 700})
        entries = normalize_failure(failure)
        self.assertEqual(len(entries), 1)
        self.assertIsNone(entries[0].context)

    def test_reasonable_context_kept_verbatim(self) -> None:
        failure = _make_failure_event(Component.QUOTE_VALIDATION, "quote_validation", {"message": "m", "k": "v"})
        entries = normalize_failure(failure)
        self.assertEqual(entries[0].context, {"k": "v"})


class DeepCopySafetyTest(unittest.TestCase):
    def test_normalize_failure_does_not_mutate_input(self) -> None:
        failure = _make_failure_event(Component.IMA, "not_in_allowlist", {"message": "m", "path": "/p"})
        snapshot = copy.deepcopy(failure.events[0].context)
        normalize_failure(failure)
        self.assertEqual(failure.events[0].context, snapshot)


if __name__ == "__main__":
    unittest.main()
