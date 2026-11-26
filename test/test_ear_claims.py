"""Unit tests for the EAR claims assembly."""

import base64
import dataclasses
import itertools
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest import mock

from keylime.claims.base import EvaluationResult, FailureEntry, KeylimeClaimsError
from keylime.claims.ear import DEFAULT_VERIFIER_DEVELOPER, EAR_PROFILE, assemble_ear_claims
from keylime.claims.failures import MAX_FAILURE_ENTRIES, normalize_failure
from keylime.failure import Component, Failure

try:
    from importlib.metadata import PackageNotFoundError
except ImportError:  # pragma: no cover
    from importlib_metadata import PackageNotFoundError  # type: ignore[assignment]

_VALID_NONCE = base64.b64encode(b"x" * 32).decode()


def _make_result(
    evaluation_id: str = "default",
    status: str = "pass",
    failures: Optional[List[FailureEntry]] = None,
    policy: str = "tpm:inline",
    claims: Optional[Dict[str, Any]] = None,
) -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        evidence_id=evaluation_id,
        evidence_type="tpm",
        status=status,  # type: ignore[arg-type]
        claims=claims if claims is not None else {"pcrs": {}},
        failures=failures or [],
        policy=policy,
        policy_source="inline",
    )


class EarClaimsStructureTest(unittest.TestCase):
    def test_eat_profile_constant(self) -> None:
        claims = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://verifier.example.com")
        # Pinned to the literal wire value (design rev 0.11; a profile
        # mismatch returns HTTP 406): a bump must be a visible test change.
        self.assertEqual(claims["eat_profile"], "tag:ietf.org,2026:rats/ear#04")
        self.assertEqual(claims["eat_profile"], EAR_PROFILE)

    def test_verifier_id_contains_developer_and_build(self) -> None:
        claims = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v", verifier_build="1.2.3")
        self.assertEqual(claims["ear_verifier_id"]["developer"], DEFAULT_VERIFIER_DEVELOPER)
        self.assertEqual(claims["ear_verifier_id"]["build"], "1.2.3")

    def test_verifier_build_defaults_to_installed_version_or_unknown(self) -> None:
        claims = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v")
        build = claims["ear_verifier_id"]["build"]
        self.assertTrue(isinstance(build, str) and build)

    def test_default_build_with_missing_package(self) -> None:
        with mock.patch("keylime.claims.ear._package_version", side_effect=PackageNotFoundError):
            claims = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v")
        self.assertEqual(claims["ear_verifier_id"]["build"], "unknown")

    def test_one_submod_per_result(self) -> None:
        results = [_make_result("default"), _make_result("second")]
        claims = assemble_ear_claims(results, nonce=_VALID_NONCE, iss="https://v")
        self.assertEqual(sorted(claims["submods"].keys()), ["default", "second"])

    def test_submod_contents(self) -> None:
        result = _make_result(failures=[FailureEntry(type="tpm.ima_violation", message="m")])
        claims = assemble_ear_claims([result], nonce=_VALID_NONCE, iss="https://v")
        submod = claims["submods"]["default"]
        self.assertEqual(submod["ear_status"], "affirming")
        self.assertEqual(submod["ear_appraisal_policy_ids"], ["tpm:inline"])
        self.assertIs(submod["ear_attester_claims"], result.claims)
        self.assertEqual(submod["keylime_evidence_type"], "tpm")
        self.assertEqual(submod["keylime_policy_source"], "inline")
        self.assertNotIn("keylime_policy_fingerprint", submod)
        # Present but null until the computation lands.
        self.assertIsNone(submod["ear_trustworthiness_vector"])
        self.assertIsNone(submod["keylime_trust_anchor_fingerprints"])
        self.assertIsNone(submod["keylime_evidence_nonce"])
        self.assertEqual(
            submod["keylime_failures"],
            [{"type": "tpm.ima_violation", "message": "m", "context": None}],
        )

    def test_duplicate_evaluation_id_raises(self) -> None:
        with self.assertRaises(KeylimeClaimsError):
            assemble_ear_claims([_make_result("default"), _make_result("default")], nonce=_VALID_NONCE, iss="https://v")

    def test_status_vocabulary_enforced_at_runtime(self) -> None:
        # The Status Literal is typing-only; a misspelled status would
        # skip the error veto and get signed as a contraindicated token.
        for bad in ("Error", "erro", None):
            with self.assertRaises(KeylimeClaimsError):
                assemble_ear_claims([_make_result(status=bad)], nonce=_VALID_NONCE, iss="https://v")  # type: ignore[arg-type]

    def test_policy_source_vocabulary_enforced_at_runtime(self) -> None:
        bad = dataclasses.replace(_make_result(), policy_source="remote")
        with self.assertRaises(KeylimeClaimsError):
            assemble_ear_claims([bad], nonce=_VALID_NONCE, iss="https://v")

    def test_status_aggregation_truth_table(self) -> None:
        # Exhaustive contract over the three statuses: "pass" is the only
        # status that can yield affirming (ALL results must pass); "fail"
        # always forces at least contraindicated while keeping per-submod
        # granularity; "error" maps to NO ear status at all — it vetoes
        # the entire token (an infrastructure failure is not an
        # attestation verdict and must never become a signed negative
        # attestation).
        for n in range(1, 4):
            for combo in itertools.product(["pass", "fail", "error"], repeat=n):
                with self.subTest(results=combo):
                    results = [_make_result(f"e{i}", status=s) for i, s in enumerate(combo)]
                    claims = assemble_ear_claims(results, nonce=_VALID_NONCE, iss="https://v")
                    if "error" in combo:
                        self.assertIsNone(claims)
                        continue
                    expected = "affirming" if all(s == "pass" for s in combo) else "contraindicated"
                    self.assertEqual(claims["ear_status"], expected)
                    for i, s in enumerate(combo):
                        self.assertEqual(
                            claims["submods"][f"e{i}"]["ear_status"],
                            "affirming" if s == "pass" else "contraindicated",
                        )

    def test_empty_results_raises(self) -> None:
        with self.assertRaises(KeylimeClaimsError):
            assemble_ear_claims([], nonce=_VALID_NONCE, iss="https://v")

    def test_fail_only_still_produces_claims_with_typed_failures(self) -> None:
        failure = Failure(Component.IMA, ["validation", "ima-ng"])
        failure.add_event("not_in_allowlist", {"message": "m", "path": "/p"}, True)

        entries = normalize_failure(failure)
        result = _make_result(status="fail", failures=entries)
        claims = assemble_ear_claims([result], nonce=_VALID_NONCE, iss="https://v")
        self.assertIsNotNone(claims)
        self.assertEqual(claims["ear_status"], "contraindicated")
        self.assertEqual(claims["submods"]["default"]["keylime_failures"][0]["type"], "tpm.ima_violation")

    def test_truncated_failure_list_carries_terminal_entry(self) -> None:
        failure = Failure(Component.IMA)
        for _ in range(MAX_FAILURE_ENTRIES + 10):
            failure.add_event("not_in_allowlist", {"message": "m"}, True)

        result = _make_result(status="fail", failures=normalize_failure(failure))
        claims = assemble_ear_claims([result], nonce=_VALID_NONCE, iss="https://v")
        emitted = claims["submods"]["default"]["keylime_failures"]
        self.assertEqual(emitted[-1]["type"], "eval.truncated")


class EarClaimsNonceTest(unittest.TestCase):
    def test_nonce_round_trips_verbatim(self) -> None:
        nonce = base64.urlsafe_b64encode(b"y" * 24).decode().rstrip("=")
        claims = assemble_ear_claims([_make_result()], nonce=nonce, iss="https://v")
        self.assertEqual(claims["eat_nonce"], nonce)

    def test_nonce_length_boundaries(self) -> None:
        for size, ok in [(15, False), (16, True), (64, True), (65, False)]:
            with self.subTest(size=size):
                nonce = base64.urlsafe_b64encode(b"z" * size).decode().rstrip("=")
                if ok:
                    claims = assemble_ear_claims([_make_result()], nonce=nonce, iss="https://v")
                    self.assertEqual(claims["eat_nonce"], nonce)
                else:
                    with self.assertRaises(KeylimeClaimsError):
                        assemble_ear_claims([_make_result()], nonce=nonce, iss="https://v")

    def test_non_base64_nonce_rejected(self) -> None:
        for nonce in ["not base64!!!", "", "<<<<", "AB-CD_EF"]:
            with self.subTest(nonce=nonce):
                with self.assertRaises(KeylimeClaimsError):
                    assemble_ear_claims([_make_result()], nonce=nonce, iss="https://v")

    def test_standard_base64_alphabet_accepted(self) -> None:
        # draft-ietf-rats-ear-04, the advertised profile, specifies base64:
        # a nonce in the standard alphabet (+ and /) is accepted and echoed
        # unchanged — the relying party compares eat_nonce byte-for-byte
        # against the challenge it sent.
        standard = base64.b64encode(b"\xfb\xff\xef\xbe" * 8).decode()
        self.assertTrue("+" in standard or "/" in standard)
        claims = assemble_ear_claims([_make_result()], nonce=standard, iss="https://v")
        self.assertEqual(claims["eat_nonce"], standard)

    def test_non_canonical_base64_lengths_rejected(self) -> None:
        # RFC 4648: a base64 length of 4k+1 characters cannot decode.
        # These are rejected by the strict decoder step.
        for length in [17, 21, 25]:
            with self.subTest(length=length):
                with self.assertRaises(KeylimeClaimsError):
                    assemble_ear_claims([_make_result()], nonce="A" * length, iss="https://v")

    def test_excess_padding_rejected(self) -> None:
        # Malformed padding must be rejected by the strict decoder.
        with self.assertRaises(KeylimeClaimsError):
            assemble_ear_claims([_make_result()], nonce="eHg" + "A" * 20 + "==", iss="https://v")

    def test_padded_base64_nonce_accepted(self) -> None:
        # The advertised profile (draft-ietf-rats-ear-04) specifies base64,
        # which pads; the padded form is accepted and echoed unchanged.
        nonce = base64.b64encode(b"p" * 17).decode()  # 17 bytes -> padded form
        claims = assemble_ear_claims([_make_result()], nonce=nonce, iss="https://v")
        self.assertEqual(claims["eat_nonce"], nonce)

    def test_draft04_example_nonce_accepted(self) -> None:
        # The 16-byte example from the review: standard padded base64.
        nonce = "AAECAwQFBgcICQoLDA0ODw=="
        claims = assemble_ear_claims([_make_result()], nonce=nonce, iss="https://v")
        self.assertEqual(claims["eat_nonce"], nonce)

    def test_input_guards_fire_even_with_error_results(self) -> None:
        # Input errors are reported even when an evaluation also errored.
        with self.assertRaises(KeylimeClaimsError):
            assemble_ear_claims([_make_result(status="error")], nonce="bad nonce!", iss="https://v")


class EarClaimsIdentityTest(unittest.TestCase):
    def test_sequential_assemblies_differ_in_jti(self) -> None:
        claims_a = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v")
        claims_b = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v")
        self.assertNotEqual(claims_a["jti"], claims_b["jti"])

    def test_explicit_jti_respected(self) -> None:
        jti = str(uuid.uuid4())
        claims = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v", jti=jti)
        self.assertEqual(claims["jti"], jti)

    def test_non_uuid_jti_rejected(self) -> None:
        with self.assertRaises(KeylimeClaimsError):
            assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v", jti="not-a-uuid")


class EarClaimsTemporalTest(unittest.TestCase):
    def test_temporal_fields_with_injected_iat(self) -> None:
        claims = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v", iat=1726000000, ttl=300)
        self.assertEqual(claims["iat"], 1726000000)
        self.assertEqual(claims["nbf"], 1726000000)
        self.assertEqual(claims["exp"], 1726000300)

    def test_iat_is_always_int(self) -> None:
        claims = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v")
        self.assertIsInstance(claims["iat"], int)
        self.assertIsInstance(claims["exp"], int)
        self.assertIsInstance(claims["nbf"], int)

    def test_float_iat_truncated(self) -> None:
        claims = assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v", iat=1726000000.75)
        self.assertEqual(claims["iat"], 1726000000)
        self.assertIsInstance(claims["iat"], int)

    def test_non_positive_ttl_rejected(self) -> None:
        for ttl in [0, -1]:
            with self.subTest(ttl=ttl):
                with self.assertRaises(KeylimeClaimsError):
                    assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v", ttl=ttl)

    def test_non_numeric_iat_rejected(self) -> None:
        # Same single-error-channel discipline as ttl: a bad iat raises
        # KeylimeClaimsError, never a raw ValueError.
        for bad_iat in ["soon", "1726000000.5abc", [1]]:
            with self.subTest(bad_iat=bad_iat):
                with self.assertRaises(KeylimeClaimsError):
                    assemble_ear_claims([_make_result()], nonce=_VALID_NONCE, iss="https://v", iat=bad_iat)


if __name__ == "__main__":
    unittest.main()
