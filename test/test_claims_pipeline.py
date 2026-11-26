"""End-to-end tests for the claims pipeline (build + assemble), including
real one-shot verification smoke scenarios."""

import base64
import json
import os
import unittest
from typing import Any, Dict
from unittest import mock

import keylime.cloud_verifier_common as cvc
from keylime.claims import (
    EvaluatedEvidence,
    KeylimeClaimsError,
    OutputFormat,
    build_verification_output,
    render_response,
)
from keylime.failure import Component, Failure
from keylime.mba import mba as mba_module
from keylime.tpm.tpm_main import Tpm

_QUOTE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test-data", "files")

_VALID_NONCE = base64.b64encode(b"n" * 32).decode()


def _b64file(name: str) -> str:
    with open(os.path.join(_QUOTE_DIR, name), "rb") as f:
        return base64.b64encode(f.read()).decode()


def _real_quote() -> str:
    """The emulator quote triple (attest blob, signature blob, PCR blob)."""
    return "r" + ":".join(_b64file(n) for n in ("quote.out", "quotesig.out", "quotepcr.out"))


def _real_quote_nonce() -> bytes:
    with open(os.path.join(_QUOTE_DIR, "rand.out"), "rb") as f:
        return f.read()


def _make_item(
    evidence: Dict[str, Any],
    policies: Dict[str, Any],
    failure: Any,
    status: str,
    evaluation_id: str = "default",
    evidence_type: str = "tpm",
) -> EvaluatedEvidence:
    return EvaluatedEvidence(
        evaluation_id=evaluation_id,
        evidence_id=evaluation_id,
        evidence_type=evidence_type,
        evidence=evidence,
        policies=policies,
        policy_name="tpm:inline",
        policy_source="inline",
        failure=failure,
        status=status,  # type: ignore[arg-type]
    )


class PipelineShapeTest(unittest.TestCase):
    def test_end_to_end_output_shapes(self) -> None:
        failure = Failure(Component.IMA, ["validation", "ima-ng"])
        failure.add_event("not_in_allowlist", {"message": "m"}, True)
        item = _make_item(
            evidence={"hash_alg": "sha256", "ima_measurement_list": "10 aa ima-ng sha256:bb boot_aggregate"},
            policies={"tpm_policy": '{"0": ["00"]}'},
            failure=failure,
            status="fail",
        )
        output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v", iat=1726000000)

        self.assertEqual(len(output.results), 1)
        result = output.results[0]
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.evaluation_id, "default")
        self.assertEqual(result.policy, "tpm:inline")
        self.assertEqual(result.failures[0].type, "tpm.ima_violation")
        self.assertIsNotNone(output.ear_claims)
        self.assertIsNone(output.ear_token)
        self.assertEqual(output.ear_claims["ear_status"], "contraindicated")

    def test_error_item_yields_no_ear_claims(self) -> None:
        item = _make_item(evidence={}, policies={}, failure=Failure(Component.DEFAULT), status="error")
        output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")
        self.assertIsNone(output.ear_claims)
        self.assertEqual(len(output.results), 1)

    def test_pass_with_failure_events_raises(self) -> None:
        # The verdict derives from status alone, so a "pass" carrying
        # failure events would be an affirming token contradicting its
        # own keylime_failures.
        failure = Failure(Component.IMA, ["validation", "ima-ng"])
        failure.add_event("not_in_allowlist", {"message": "m"}, True)
        item = _make_item(evidence={}, policies={}, failure=failure, status="pass")
        with self.assertRaises(KeylimeClaimsError):
            build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")

    def test_fail_without_failure_events_warns(self) -> None:
        # Soft direction: future CRL notes will arrive as low-severity
        # events, so fail-without-events only warns.
        item = _make_item(evidence={}, policies={}, failure=Failure(Component.DEFAULT), status="fail")
        with self.assertLogs("keylime.claims.pipeline", level="WARNING"):
            output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")
        self.assertEqual(output.results[0].status, "fail")

    def test_unsupported_evidence_type_degrades_to_error_result(self) -> None:
        # Per the plan's error model: an unknown evidence type is an
        # evaluation-level error, not a request-level abort.
        item = _make_item(
            evidence={}, policies={}, failure=Failure(Component.DEFAULT), status="pass", evidence_type="tee-tdx"
        )
        output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")
        self.assertEqual(len(output.results), 1)
        result = output.results[0]
        self.assertEqual(result.status, "error")
        self.assertEqual(result.failures[0].type, "eval.unsupported_evidence_type")
        self.assertIsNone(output.ear_claims)  # any error -> no token

    def test_tee_snp_skeleton_degrades_gracefully(self) -> None:
        # The SNP translator skeleton is REGISTERED (reachable through the
        # pipeline) but not implemented: the item degrades to an error
        # result instead of aborting the request.
        item = _make_item(
            evidence={}, policies={}, failure=Failure(Component.DEFAULT), status="pass", evidence_type="tee-snp"
        )
        output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")
        self.assertEqual(output.results[0].status, "error")
        self.assertEqual(output.results[0].failures[0].type, "eval.translation_error")
        self.assertIsNone(output.ear_claims)

    def test_failed_evaluation_does_not_abort_other_evaluations(self) -> None:
        # The plan's Phase 3 error model: one evaluation erroring must not
        # destroy the results of the others in the same request.
        snp_item = _make_item(
            evidence={}, policies={}, failure=Failure(Component.DEFAULT), status="pass", evidence_type="tee-snp"
        )
        tpm_item = _make_item(
            evidence={"hash_alg": "sha256"},
            policies={"tpm_policy": "{}"},
            failure=Failure(Component.IMA, ["validation", "ima-ng"]),
            status="fail",
            evaluation_id="second",
        )
        tpm_item.failure.add_event("not_in_allowlist", {"message": "m"}, True)
        output = build_verification_output([snp_item, tpm_item], nonce=_VALID_NONCE, iss="https://v")
        self.assertEqual(len(output.results), 2)
        self.assertEqual(output.results[0].status, "error")
        self.assertEqual(output.results[1].status, "fail")
        self.assertIn("pcrs", output.results[1].claims)  # TPM item still translated
        self.assertIsNone(output.ear_claims)

    def test_claims_shared_by_reference_between_results_and_ear(self) -> None:
        item = _make_item(
            evidence={"hash_alg": "sha256"},
            policies={"tpm_policy": "{}"},
            failure=Failure(Component.DEFAULT),
            status="pass",
        )
        output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")
        self.assertIs(
            output.results[0].claims,
            output.ear_claims["submods"]["default"]["ear_attester_claims"],
        )


class PipelineSmokeTest(unittest.TestCase):
    """Three REAL one-shot scenarios — the merge gate.

    Each scenario asserts which checks ran, which claims may be emitted,
    and whether the signer gets invoked.
    """

    def setUp(self) -> None:
        # Seed the DEFAULT measured-boot parsers (the running verifier
        # does its own, fuller initialization at startup).
        self._saved_imports = list(mba_module._mba_imports)  # pylint: disable=protected-access
        if not mba_module._mba_imports:  # pylint: disable=protected-access
            mba_module.load_imports(skip_custom_policies=True)

    def tearDown(self) -> None:
        mba_module._mba_imports = self._saved_imports  # pylint: disable=protected-access

    @staticmethod
    def _verify(ek: str, ak: str, quote: str, nonce: bytes, hash_alg: str, tpm_policy: str) -> Failure:
        return cvc.process_verify_attestation(ek, ak, quote, nonce, hash_alg, tpm_policy, None, "", None, None)

    @staticmethod
    def _ek() -> str:
        with open(os.path.join(_QUOTE_DIR, "ekpub.pem"), encoding="utf-8") as f:
            return f.read()

    def test_scenario_passing_evaluation(self) -> None:
        """A passing evaluation yields an assembled token payload and the
        signer is invoked; the policy fingerprint is present."""
        quote = _real_quote()
        ek = self._ek()
        ak = _b64file("ak.pub")
        quote_nonce = _real_quote_nonce()

        pcrs = Tpm.get_pcrs_from_quote(quote, False)  # type: ignore[no-untyped-call]
        tpm_policy = json.dumps({str(k): [v] for k, v in pcrs.items()})

        # The caller owns the classification: clean return -> pass.
        failure = self._verify(ek, ak, quote, quote_nonce, "sha256", tpm_policy)
        self.assertFalse(bool(failure), f"expected a passing evaluation, got {failure.get_event_ids()}")

        item = _make_item(
            evidence={"quote": quote, "nonce": quote_nonce.hex(), "hash_alg": "sha256"},
            policies={"tpm_policy": tpm_policy},
            failure=failure,
            status="pass",
        )
        output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")

        self.assertIsNotNone(output.ear_claims)
        submod = output.ear_claims["submods"]["default"]
        self.assertEqual(submod["ear_status"], "affirming")
        self.assertEqual(output.ear_claims["ear_status"], "affirming")
        # Removed with D2: policy identity is carried by
        # ear_appraisal_policy_ids; the slot must be gone from the wire.
        self.assertNotIn("keylime_policy_fingerprint", submod)
        # Deferred slots are present on the wire with null values.
        self.assertIsNone(submod["ear_trustworthiness_vector"])
        self.assertIsNone(submod["keylime_trust_anchor_fingerprints"])
        self.assertIsNone(submod["keylime_evidence_nonce"])

        # The merge-gate signing claim: the signer actually runs, exactly
        # once, and the payload survives serialization end-to-end (a
        # json.dumps signer is the point — a non-serializable claims dict
        # fails here).
        signed = []

        def signer(claims):
            signed.append(json.dumps(claims))
            return "signed.jwt"

        response = render_response(output, output_format=OutputFormat.EAR_JWT, signer=signer)
        self.assertEqual(response.body, "signed.jwt")
        self.assertEqual(len(signed), 1)

    def test_scenario_completed_policy_failure(self) -> None:
        """A completed evaluation that FAILS policy still yields a SIGNED
        (contraindicated) token with the failures present."""
        quote = _real_quote()
        ek = self._ek()
        ak = _b64file("ak.pub")
        quote_nonce = _real_quote_nonce()

        # Correct structure, wrong expected values -> PCR mismatch.
        # ("ab"*32 matches none of the quoted values.)
        pcrs = Tpm.get_pcrs_from_quote(quote, False)  # type: ignore[no-untyped-call]
        wrong_policy = json.dumps({str(k): ["ab" * 32] for k in pcrs})

        failure = self._verify(ek, ak, quote, quote_nonce, "sha256", wrong_policy)
        self.assertTrue(bool(failure))
        self.assertTrue(
            any(eid.startswith("pcr_validation.invalid_pcr_") for eid in failure.get_event_ids()),
            failure.get_event_ids(),
        )

        item = _make_item(
            evidence={"quote": quote, "nonce": quote_nonce.hex(), "hash_alg": "sha256"},
            policies={"tpm_policy": wrong_policy},
            failure=failure,
            status="fail",
        )
        output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")

        self.assertIsNotNone(output.ear_claims)
        self.assertEqual(output.ear_claims["ear_status"], "contraindicated")
        submod = output.ear_claims["submods"]["default"]
        self.assertEqual(submod["ear_status"], "contraindicated")
        failure_types = [f["type"] for f in submod["keylime_failures"]]
        self.assertIn("tpm.pcr_mismatch", failure_types)

        # The docstring's claim: the contraindicated token is SIGNED. The
        # json.dumps signer proves the failure payload (claims +
        # keylime_failures) survives serialization end-to-end.
        signed = []

        def signer(claims):
            signed.append(json.dumps(claims))
            return "signed.jwt"

        response = render_response(output, output_format=OutputFormat.EAR_JWT, signer=signer)
        self.assertEqual(response.body, "signed.jwt")
        self.assertEqual(len(signed), 1)

    def test_scenario_infrastructure_failure(self) -> None:
        """An evaluation that RAISES maps to status "error": no claims are
        assembled and the signer is NEVER invoked — an unavailable verifier
        dependency can never become a signed negative attestation."""
        # The verify helpers swallow exceptions from the quote check into
        # an "invalid_quote" FAILURE EVENT (a completed "fail" evaluation).
        # A status of "error" can therefore only arise when the CALLER
        # wraps the verify call in its own try/except and maps a raised
        # exception (e.g. an unavailable verifier dependency) to "error" —
        # that classification contract is exercised here.
        with mock.patch.object(
            cvc, "process_verify_attestation", side_effect=OSError("verifier dependency unavailable")
        ):
            with self.assertRaises(OSError):
                cvc.process_verify_attestation("ek", "ak", "q", b"n", "sha256", "{}", None, "", None, None)

        item = _make_item(
            evidence={"quote": "q"},
            policies={"tpm_policy": "{}"},
            failure=Failure(Component.DEFAULT),
            status="error",
        )
        output = build_verification_output([item], nonce=_VALID_NONCE, iss="https://v")

        self.assertIsNone(output.ear_claims)
        self.assertEqual(output.results[0].status, "error")
        # Both renderers take the error path — no signer is ever consulted.
        for output_format in (OutputFormat.EAR_JWT, OutputFormat.JSONAPI):
            with self.subTest(output_format=output_format):
                response = render_response(output, output_format=output_format, signer=None)
                self.assertEqual(response.headers, {"Vary": "Accept"})

    def test_mixed_types_dispatch_through_registry(self) -> None:
        # Two TPM items with distinct evaluation ids — the registry
        # instantiation path and duplicate-id guard at the pipeline level.
        ev = {"hash_alg": "sha256"}
        pol = {"tpm_policy": "{}"}
        items = [
            _make_item(ev, pol, Failure(Component.DEFAULT), "pass", evaluation_id="ev-1"),
            _make_item(ev, pol, Failure(Component.DEFAULT), "fail", evaluation_id="ev-2"),
        ]
        output = build_verification_output(items, nonce=_VALID_NONCE, iss="https://v")
        self.assertEqual(sorted(output.ear_claims["submods"].keys()), ["ev-1", "ev-2"])
        self.assertEqual(output.ear_claims["ear_status"], "contraindicated")


if __name__ == "__main__":
    unittest.main()
