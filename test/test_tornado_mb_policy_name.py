"""
Unit tests that cover the two call-sites in cloud_verifier_tornado.py where
mb_policy_name is forwarded to the verifier-common layer:

  1. VerifyEvidenceHandler._tpm_verify()   → process_verify_attestation(... mb_policy_name=...)
  2. invoke_get_quote()                    → process_quote_response(... mb_policy_name=...)

Both sites were introduced by PR #1879 and had 0 % patch-coverage because no
unit test exercised them.  These tests keep the mock surface as small as
possible and verify the argument wiring without running any real TPM logic.
"""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import keylime.cloud_verifier_tornado as cvt
from keylime.cloud_verifier_tornado import VerifyEvidenceHandler
from keylime.failure import Component, Failure

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _empty_failure() -> Failure:
    return Failure(Component.DEFAULT)


# ---------------------------------------------------------------------------
# 1.  VerifyEvidenceHandler._tpm_verify()
# ---------------------------------------------------------------------------


class TestVerifyEvidenceHandlerTpmVerify(unittest.TestCase):
    """
    Covers keylime/cloud_verifier_tornado.py lines ~1894-1906
    (the process_verify_attestation call with mb_policy_name).
    """

    def _make_handler(self):
        """
        Build a VerifyEvidenceHandler without a running tornado Application or
        Request object by bypassing __init__ and setting only the attributes
        that _tpm_verify() actually reads (none — it only uses module-level
        symbols).
        """
        handler = VerifyEvidenceHandler.__new__(VerifyEvidenceHandler)
        return handler

    # --- minimal valid data dict that passes all the early-return guards ----

    _VALID_DATA = {
        "quote": "r/1RDR4AYAC...",
        "nonce": "deadbeef",
        "hash_alg": "sha256",
        "tpm_ek": "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
        "tpm_ak": "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
        "tpm_policy": '{"0": ["0000000000000000000000000000000000000000000000000000000000000000"]}',
        # optional fields are left absent so we don't trigger extra paths
    }

    def test_mb_policy_name_read_from_config_and_forwarded(self):
        """
        _tpm_verify reads measured_boot_policy_name from config and forwards it
        to process_verify_attestation as the mb_policy_name keyword argument.
        """
        handler = self._make_handler()

        with (
            patch("keylime.cloud_verifier_tornado.cloud_verifier_common.process_verify_attestation") as mock_pva,
            patch("keylime.cloud_verifier_tornado.ima.deserialize_runtime_policy") as mock_drp,
            patch("keylime.cloud_verifier_tornado.config.get", return_value="my-mb-policy") as mock_cfg,
        ):
            mock_drp.return_value = None
            mock_pva.return_value = _empty_failure()

            _data, _failure = handler._tpm_verify(dict(self._VALID_DATA))  # pylint: disable=protected-access

        # config.get must have been called for measured_boot_policy_name
        mock_cfg.assert_any_call("verifier", "measured_boot_policy_name", fallback="accept-all")

        # process_verify_attestation must have been called with mb_policy_name
        mock_pva.assert_called_once()
        call_kw = mock_pva.call_args.kwargs
        self.assertEqual(
            call_kw.get("mb_policy_name"),
            "my-mb-policy",
            "mb_policy_name must be forwarded from config to process_verify_attestation",
        )

    def test_default_policy_name_is_accept_all(self):
        """
        When config.get returns the fallback, 'accept-all' is passed through.
        """
        handler = self._make_handler()

        # Return the fallback value (simulates missing config key)
        with (
            patch("keylime.cloud_verifier_tornado.cloud_verifier_common.process_verify_attestation") as mock_pva,
            patch("keylime.cloud_verifier_tornado.ima.deserialize_runtime_policy", return_value=None),
            patch("keylime.cloud_verifier_tornado.config.get", return_value="accept-all"),
        ):  # fallback
            mock_pva.return_value = _empty_failure()
            handler._tpm_verify(dict(self._VALID_DATA))  # pylint: disable=protected-access

        self.assertEqual(mock_pva.call_args.kwargs.get("mb_policy_name"), "accept-all")


# ---------------------------------------------------------------------------
# 2.  invoke_get_quote()
# ---------------------------------------------------------------------------


# A minimal HTTP response object with real (non-mock) attribute types so
# ``response.status_code != 200`` comparisons work correctly.
class _FakeHTTPResponse:
    def __init__(self, results_body: dict):
        self.status_code: int = 200  # real int
        self.body: bytes = json.dumps({"results": results_body}).encode()


class TestInvokeGetQuoteMbPolicyName(unittest.IsolatedAsyncioTestCase):
    """
    Covers keylime/cloud_verifier_tornado.py lines ~2220-2226
    (the process_quote_response call with mb_policy_name inside invoke_get_quote).

    Uses IsolatedAsyncioTestCase so each test gets a fresh event loop.
    tornado_requests.request is replaced with an AsyncMock that directly
    returns a _FakeHTTPResponse, matching the ``response = await res`` pattern
    in invoke_get_quote.
    """

    _AGENT = {
        "agent_id": "test-agent-uuid",
        "ip": "127.0.0.1",
        "port": 9002,
        "supported_version": "2.5",
        "ssl_context": None,
        "pending_event": None,
        "provide_V": False,
    }

    _RESULTS = {
        "quote": "r/1RDR4AYAC...",
        "hash_alg": "sha256",
        "enc_alg": "rsa2048",
        "sign_alg": "rsassa",
        "pubkey": "",
    }

    async def _run_invoke_get_quote(self, config_policy_name: str) -> MagicMock:
        """
        Run invoke_get_quote with heavy mocking and return the mock for
        process_quote_response so callers can assert on it.
        """
        # AsyncMock so that ``res = tornado_requests.request(...)`` returns a
        # coroutine whose await result is _FakeHTTPResponse.
        mock_request = AsyncMock(return_value=_FakeHTTPResponse(self._RESULTS))
        mock_pqr = MagicMock(return_value=_empty_failure())

        with (
            patch("keylime.cloud_verifier_tornado.tornado_requests.request", mock_request),
            patch(
                "keylime.cloud_verifier_tornado.cloud_verifier_common.prepare_get_quote",
                return_value={"nonce": "abc", "mask": "0x0", "ima_ml_entry": 0},
            ),
            patch("keylime.cloud_verifier_tornado.cloud_verifier_common.process_quote_response", mock_pqr),
            patch("keylime.cloud_verifier_tornado.ima.deserialize_runtime_policy", return_value=None),
            patch("keylime.cloud_verifier_tornado.get_AgentAttestStates") as mock_gas,
            patch("keylime.cloud_verifier_tornado.asyncio.ensure_future", side_effect=lambda coro: coro.close()),
            patch("keylime.cloud_verifier_tornado.store_attestation_state"),
            patch("keylime.cloud_verifier_tornado.shutdown.is_shutting_down", return_value=False),
            patch("keylime.cloud_verifier_tornado.rmc", None),
            patch("keylime.cloud_verifier_tornado.config.get", return_value=config_policy_name),
        ):
            mock_gas.return_value.get_by_agent_id.return_value = MagicMock()
            await cvt.invoke_get_quote(
                dict(self._AGENT),
                mb_policy="{}",
                runtime_policy="{}",
                need_pubkey=False,
            )

        return mock_pqr

    async def test_mb_policy_name_forwarded_to_process_quote_response(self):
        """
        invoke_get_quote reads measured_boot_policy_name from config and
        forwards it to process_quote_response as the mb_policy_name kwarg.
        """
        mock_pqr = await self._run_invoke_get_quote("example-policy")

        mock_pqr.assert_called_once()
        self.assertEqual(
            mock_pqr.call_args.kwargs.get("mb_policy_name"),
            "example-policy",
            "mb_policy_name must be forwarded from config to process_quote_response",
        )

    async def test_default_policy_name_fallback(self):
        """
        When config returns the fallback, 'accept-all' reaches process_quote_response.
        """
        mock_pqr = await self._run_invoke_get_quote("accept-all")

        mock_pqr.assert_called_once()
        self.assertEqual(
            mock_pqr.call_args.kwargs.get("mb_policy_name"),
            "accept-all",
        )


if __name__ == "__main__":
    unittest.main()
