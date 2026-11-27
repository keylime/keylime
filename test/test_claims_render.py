"""Unit tests for response rendering (dispatch, both renderers, signer
isolation, idempotent issuance, headers)."""

import copy
import unittest
from typing import Any, Dict

from keylime.claims import (
    EvaluationResult,
    KeylimeClaimsError,
    OutputFormat,
    RenderedResponse,
    VerificationOutput,
    render_response,
)
from keylime.claims.ear import EAR_PROFILE
from keylime.claims.renderers.issuance import issue_token

_SENTINEL_TOKEN = "sentinel.signed.token"


def _body_dict(response: RenderedResponse) -> Dict[str, Any]:
    """Response body as a dict — the JSON:API/problem-details paths only."""
    assert isinstance(response.body, dict)
    return response.body


def _sentinel_signer(_claims: Dict[str, Any]) -> str:
    return _SENTINEL_TOKEN


def _make_result(evaluation_id: str = "default", status: str = "pass") -> EvaluationResult:
    return EvaluationResult(
        evaluation_id=evaluation_id,
        evidence_id=evaluation_id,
        evidence_type="tpm",
        status=status,  # type: ignore[arg-type]
        claims={"pcrs": {"0": "aa"}},
        failures=[],
        policy="tpm:inline",
        policy_source="inline",
    )


def _make_output(status: str = "pass") -> VerificationOutput:
    result = _make_result(status=status)
    if status == "error":
        return VerificationOutput(results=[result], ear_claims=None)
    submods = {
        result.evaluation_id: {
            "ear_status": "affirming" if status == "pass" else "contraindicated",
            "ear_appraisal_policy_ids": [result.policy],
            "ear_attester_claims": result.claims,
            "keylime_evidence_type": "tpm",
            "keylime_policy_source": "inline",
            "keylime_failures": [],
        }
    }
    ear_claims = {
        "eat_profile": EAR_PROFILE,
        "iss": "https://v",
        "iat": 1726000000,
        "nbf": 1726000000,
        "exp": 1726000300,
        "jti": "550e8400-e29b-41d4-a716-446655440000",
        "eat_nonce": "nonce",
        "ear_verifier_id": {"developer": "d", "build": "b"},
        "ear_status": "affirming" if status == "pass" else "contraindicated",
        "submods": submods,
    }
    return VerificationOutput(results=[result], ear_claims=ear_claims)


class DispatchTest(unittest.TestCase):
    def test_dispatch_routes_to_registered_renderer(self) -> None:
        response = render_response(_make_output(), output_format=OutputFormat.EAR_JWT, signer=_sentinel_signer)
        self.assertEqual(response.body, _SENTINEL_TOKEN)
        response = render_response(_make_output(), output_format=OutputFormat.JSONAPI, signer=_sentinel_signer)
        self.assertIn("data", response.body)

    def test_unknown_format_raises(self) -> None:
        with self.assertRaises(KeylimeClaimsError):
            render_response(_make_output(), output_format="application/no-such-format", signer=_sentinel_signer)  # type: ignore[arg-type]


class EarJwtRendererTest(unittest.TestCase):
    def test_body_is_the_token_string(self) -> None:
        response = render_response(_make_output(), output_format=OutputFormat.EAR_JWT, signer=_sentinel_signer)
        self.assertEqual(response.body, _SENTINEL_TOKEN)
        self.assertEqual(response.content_type, f'application/eat+jwt; eat_profile="{EAR_PROFILE}"')

    def test_error_output_yields_problem_details(self) -> None:
        response = render_response(
            _make_output(status="error"), output_format=OutputFormat.EAR_JWT, signer=_sentinel_signer
        )
        self.assertEqual(response.content_type, "application/problem+json")
        self.assertIsInstance(response.body, dict)
        # An infra error must never derive as 2xx; the plan pins 502 (the
        # verifier reports an upstream/pipeline failure).
        self.assertEqual(response.status, 502)
        self.assertEqual(_body_dict(response)["status"], 502)

    def test_missing_signer_with_claims_raises(self) -> None:
        with self.assertRaises(KeylimeClaimsError):
            render_response(_make_output(), output_format=OutputFormat.EAR_JWT, signer=None)

    def test_missing_signer_on_error_path_is_fine(self) -> None:
        # No claims were assembled, so no signer is needed.
        response = render_response(_make_output(status="error"), output_format=OutputFormat.EAR_JWT, signer=None)
        self.assertEqual(response.content_type, "application/problem+json")
        self.assertEqual(response.status, 502)


class JsonApiRendererTest(unittest.TestCase):
    def test_envelope_carries_the_token(self) -> None:
        output = _make_output()
        response = render_response(output, output_format=OutputFormat.JSONAPI, signer=_sentinel_signer)
        self.assertEqual(response.content_type, "application/vnd.api+json")
        self.assertEqual(_body_dict(response)["data"]["attributes"]["attestation_result"], _SENTINEL_TOKEN)
        self.assertEqual(output.ear_token, _SENTINEL_TOKEN)
        self.assertIsNone(response.status)

    def test_error_output_yields_null_attestation_result(self) -> None:
        response = render_response(
            _make_output(status="error"), output_format=OutputFormat.JSONAPI, signer=_sentinel_signer
        )
        self.assertIsNone(_body_dict(response)["data"]["attributes"]["attestation_result"])
        # Per the plan, JSON:API evaluation-level errors are HTTP 200: the
        # request is valid, the verifier cannot evaluate (some of) it.
        # None derives the 2xx from the envelope body.
        self.assertIsNone(response.status)

    def test_missing_signer_with_claims_raises(self) -> None:
        with self.assertRaises(KeylimeClaimsError):
            render_response(_make_output(), output_format=OutputFormat.JSONAPI, signer=None)

    def test_missing_signer_on_error_path_is_fine(self) -> None:
        # No claims were assembled, so no signer is needed (symmetric
        # with the raw-JWT renderer's error path).
        response = render_response(_make_output(status="error"), output_format=OutputFormat.JSONAPI, signer=None)
        self.assertIsNone(_body_dict(response)["data"]["attributes"]["attestation_result"])


class IdempotentIssuanceTest(unittest.TestCase):
    def test_second_render_reuses_issued_token(self) -> None:
        calls = []

        def counting_signer(_claims: Dict[str, Any]) -> str:
            calls.append(1)
            return f"token-{len(calls)}"

        output = _make_output()
        first = render_response(output, output_format=OutputFormat.EAR_JWT, signer=counting_signer)
        second = render_response(output, output_format=OutputFormat.EAR_JWT, signer=counting_signer)
        self.assertEqual(len(calls), 1)  # signer called exactly once
        self.assertEqual(first.body, "token-1")
        self.assertEqual(second.body, "token-1")  # reused, not re-signed

    def test_cross_format_reuses_issued_token(self) -> None:
        calls = []

        def counting_signer(_claims: Dict[str, Any]) -> str:
            calls.append(1)
            return f"token-{len(calls)}"

        output = _make_output()
        ear = render_response(output, output_format=OutputFormat.EAR_JWT, signer=counting_signer)
        api = render_response(output, output_format=OutputFormat.JSONAPI, signer=counting_signer)
        self.assertEqual(len(calls), 1)
        self.assertEqual(_body_dict(api)["data"]["attributes"]["attestation_result"], ear.body)


class HeadersTest(unittest.TestCase):
    def test_every_renderer_every_path_sets_vary_accept(self) -> None:
        cases = [
            (OutputFormat.EAR_JWT, "pass", _sentinel_signer),
            (OutputFormat.EAR_JWT, "error", _sentinel_signer),
            (OutputFormat.EAR_JWT, "error", None),
            (OutputFormat.JSONAPI, "pass", _sentinel_signer),
            (OutputFormat.JSONAPI, "error", _sentinel_signer),
        ]
        for output_format, status, signer in cases:
            with self.subTest(output_format=output_format, status=status):
                response = render_response(_make_output(status=status), output_format=output_format, signer=signer)
                self.assertEqual(response.headers, {"Vary": "Accept"})


class SignerErrorTest(unittest.TestCase):
    """A failing signer (bad key, crypto error, misconfig) is an
    infrastructure error: it must surface as KeylimeClaimsError through
    the package's single error channel, never escape render() raw."""

    class _CryptoError(Exception):
        pass

    @staticmethod
    def _raising_signer(_claims: Dict[str, Any]) -> str:
        raise SignerErrorTest._CryptoError("bad key")

    def test_signer_failure_wrapped_for_both_formats(self) -> None:
        for output_format in (OutputFormat.EAR_JWT, OutputFormat.JSONAPI):
            with self.subTest(output_format=output_format):
                with self.assertRaises(KeylimeClaimsError) as ctx:
                    render_response(_make_output(), output_format=output_format, signer=self._raising_signer)
                # The original cause stays visible for diagnostics.
                self.assertIsInstance(ctx.exception.__cause__, self._CryptoError)

    def test_keylime_claims_error_from_signer_passthrough(self) -> None:
        # A signer that already raises the package's own error type is
        # re-raised as-is, not double-wrapped.
        sentinel = KeylimeClaimsError("already wrapped")

        def wrapping_signer(_claims: Dict[str, Any]) -> str:
            raise sentinel

        with self.assertRaises(KeylimeClaimsError) as ctx:
            render_response(_make_output(), output_format=OutputFormat.EAR_JWT, signer=wrapping_signer)
        self.assertIs(ctx.exception, sentinel)


class MutationIsolationTest(unittest.TestCase):
    def test_renderers_do_not_mutate_shared_claims(self) -> None:
        output = _make_output()
        snapshot = copy.deepcopy(output.ear_claims)
        render_response(output, output_format=OutputFormat.EAR_JWT, signer=_sentinel_signer)
        render_response(output, output_format=OutputFormat.JSONAPI, signer=_sentinel_signer)
        self.assertEqual(output.ear_claims, snapshot)
        self.assertEqual(output.results[0].claims, {"pcrs": {"0": "aa"}})

    def test_mutating_signer_cannot_change_shared_claims(self) -> None:
        def mutating_signer(claims: Dict[str, Any]) -> str:
            claims["injected"] = "by the signer"
            claims["submods"]["default"]["ear_status"] = (
                "affirming" if claims["submods"]["default"]["ear_status"] != "affirming" else "tampered"
            )
            return "signed"

        for output_format in (OutputFormat.EAR_JWT, OutputFormat.JSONAPI):
            with self.subTest(output_format=output_format):
                output = _make_output(status="fail")
                snapshot = copy.deepcopy(output.ear_claims)
                render_response(output, output_format=output_format, signer=mutating_signer)
                self.assertEqual(output.ear_claims, snapshot)  # deep copy isolated the signer

    def test_bad_signer_returns_rejected_and_not_cached(self) -> None:
        # The token-type check is an issuance invariant of BOTH renderers:
        # a None/empty/non-string signer return must raise and must never
        # be cached into ear_token (a cached None is indistinguishable
        # from "not yet issued").
        for bad_return in (None, "", 123):
            for output_format in (OutputFormat.EAR_JWT, OutputFormat.JSONAPI):
                with self.subTest(bad_return=bad_return, output_format=output_format):
                    output = _make_output()

                    def bad_signer(_claims: Dict[str, Any], _r=bad_return) -> Any:
                        return _r

                    with self.assertRaises(KeylimeClaimsError):
                        render_response(output, output_format=output_format, signer=bad_signer)
                    self.assertIsNone(output.ear_token)

    def test_issue_token_rejects_missing_claims(self) -> None:
        # The renderers guard ear_claims before calling, so this branch
        # is defensive — but the helper must not trust its callers: an
        # infra-error output (ear_claims None) must never reach signing.
        output = _make_output(status="error")
        with self.assertRaises(KeylimeClaimsError) as ctx:
            issue_token(output, signer=_sentinel_signer, format_name="EAR_JWT")
        self.assertIn("requires assembled EAR claims", str(ctx.exception))
        self.assertIsNone(output.ear_token)  # nothing was issued or cached


if __name__ == "__main__":
    unittest.main()
