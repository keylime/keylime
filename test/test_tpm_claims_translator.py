"""Unit tests for the TPM claims translator."""

import base64
import copy
import json
import os
import struct
import unittest
from typing import Any, Dict, List, Optional

from keylime.claims.base import EvaluatedEvidence
from keylime.claims.translators.tpm import TpmClaimsTranslator
from keylime.failure import Component, Failure
from keylime.mba import mba as mba_module

# Emulator quote artifacts (raw binary) used to assemble a realistic quote
# string; the first token (the attestation blob) is ignored by the PCR
# extraction we exercise, so the real blob is reused for realism.
_QUOTE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test-data", "files")

MB_LOG_B64 = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "mb_log.b64"
)

# sha256 (TPM_ALG_SHA256) in the TPM algorithm-id space
_TPM_ALG_SHA256 = 0x000B

# PCRs and digest values for the synthetic quote fixture
_FX_PCRS = {0: b"\x11" * 32, 1: b"\x22" * 32, 10: b"\xaa" * 32}


def _build_pcrblob(pcr_ids: List[int], digests: List[bytes], hash_alg: int = _TPM_ALG_SHA256) -> bytes:
    """Construct a synthetic quote PCR blob.

    Layout (little-endian "in-memory" Intel format consumed by the quote
    parser): a select count, EXACTLY 16 TPMS_PCR_SELECTION entries
    (hash alg + sizeof-select + 3 select bytes + 2 pad bytes), a digest
    count, then one TPML_DIGEST block per selected PCR (count + 8
    TPM2B_DIGEST slots of fixed 64-byte width each).
    """
    select = 0
    for pcr in pcr_ids:
        select |= 1 << pcr

    buf = struct.pack("<I", 1)  # TPML_PCR_SELECTION count
    for i in range(16):
        if i == 0:
            buf += struct.pack("<HB", hash_alg, 3)
            buf += select.to_bytes(3, "little")
            buf += b"\x00\x00"  # alignment
        else:
            buf += struct.pack("<HB", 0, 0)
            buf += b"\x00" * 5

    buf += struct.pack("<I", len(digests))  # TPML_DIGEST count
    for digest in digests:
        buf += struct.pack("<I", 1)  # per-block count (unused by the parser)
        for slot in range(8):
            if slot == 0:
                buf += struct.pack("<H", len(digest)) + digest
                buf += b"\x00" * (64 - len(digest))
            else:
                buf += struct.pack("<H", 0) + b"\x00" * 64
    return buf


def _build_sigblob(hash_alg: int = _TPM_ALG_SHA256) -> bytes:
    """6-byte big-endian header; the hash algorithm sits at offset 2."""
    return struct.pack(">HHH", 0x00FF, hash_alg, 0)


def _build_quote_fixture(pcrs: Optional[Dict[int, bytes]] = None) -> str:
    """Assemble an 'r<quote>:<sig>:<pcrs>' quote string from synthetic blobs."""
    if pcrs is None:
        pcrs = _FX_PCRS
    with open(os.path.join(_QUOTE_DIR, "quote.out"), "rb") as f:
        quoteblob = f.read()
    pcr_ids = sorted(pcrs.keys())
    digests = [pcrs[i] for i in pcr_ids]
    pcrblob = _build_pcrblob(pcr_ids, digests)
    sigblob = _build_sigblob()
    return "r" + ":".join(
        base64.b64encode(part).decode() for part in (quoteblob, sigblob, pcrblob)
    )


def _load_mb_log() -> str:
    # The fixture contains embedded newlines; load it the way the measured
    # boot parsing tests do (read + strip newlines).
    with open(MB_LOG_B64, encoding="utf-8") as f:
        return f.read().strip().replace("\n", "")


def _make_ima_list(lines: int, boot_aggregate: Optional[str] = None) -> str:
    digest = boot_aggregate or ("e4cb9f5709c88376b5fc3743cd88e76b9aae8f3d992d845678de5215edb31216")
    first = f"10 {'0' * 40} ima-ng sha256:{digest} boot_aggregate"
    rest = [f"10 {'0' * 40} ima-ng sha256:{'f' * 64} /bin/somefile_{i}" for i in range(lines - 1)]
    return "\n".join([first] + rest)


def _make_item(evidence: Dict[str, Any], failure: Any = None, status: str = "pass") -> EvaluatedEvidence:
    return EvaluatedEvidence(
        evaluation_id="default",
        evidence_id="default",
        evidence_type="tpm",
        evidence=evidence,
        policies={"tpm_policy": {}},
        policy_name="tpm:inline",
        policy_source="inline",
        failure=failure if failure is not None else Failure(Component.DEFAULT),
        status=status,  # type: ignore[arg-type]
    )


class TpmClaimsTranslatorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.translator = TpmClaimsTranslator()
        # Test isolation: _mba_imports is process-global and other tests
        # may have loaded custom measured-boot parsers; snapshot, reset,
        # and seed the defaults so these tests are order-independent.
        self._mba_module = mba_module
        self._saved_imports = list(mba_module._mba_imports)  # pylint: disable=protected-access
        mba_module._mba_imports = []  # pylint: disable=protected-access
        mba_module.load_imports(skip_custom_policies=True)

    def tearDown(self) -> None:
        self._mba_module._mba_imports = self._saved_imports  # pylint: disable=protected-access

    # -- PCR extraction ------------------------------------------------

    def test_pcrs_from_synthetic_quote(self) -> None:
        item = _make_item({"quote": _build_quote_fixture(), "hash_alg": "sha256"})
        claims = self.translator.translate(item)
        self.assertEqual(sorted(claims["pcrs"].keys()), ["0", "1", "10"])
        self.assertEqual(claims["pcrs"]["0"], (_FX_PCRS[0].hex()))
        self.assertEqual(claims["pcrs"]["10"], (_FX_PCRS[10].hex()))
        for value in claims["pcrs"].values():
            self.assertEqual(value, value.lower())

    # -- submitted IMA count -----------------------------------------

    def test_ima_entries_count_with_empty_failure(self) -> None:
        item = _make_item({"ima_measurement_list": _make_ima_list(1234)})
        claims = self.translator.translate(item)
        self.assertEqual(claims["ima"]["entries_count"], 1234)
        self.assertEqual(claims["ima"]["violations"], [])

    # -- IMA violations from failure events ------------------------------

    def test_ima_violations_from_failure_events(self) -> None:
        failure = Failure(Component.IMA, ["validation", "ima-ng"])
        failure.add_event(
            "not_in_allowlist", {"message": "file not in allowlist", "context": "/usr/bin/evil"}, True
        )
        item = _make_item({"ima_measurement_list": _make_ima_list(5)}, failure=failure, status="fail")
        claims = self.translator.translate(item)
        self.assertEqual(len(claims["ima"]["violations"]), 1)
        violation = claims["ima"]["violations"][0]
        self.assertEqual(violation["type"], "tpm.ima_violation")
        self.assertEqual(violation["message"], "file not in allowlist")
        self.assertEqual(violation["context"], {"context": "/usr/bin/evil"})

    # -- measured boot ------------------------------------------------

    def test_measured_boot_from_fixture(self) -> None:
        item = _make_item({"mb_log": _load_mb_log(), "hash_alg": "sha256"})
        claims = self.translator.translate(item)
        self.assertEqual(claims["measured_boot"]["entries_count"], 102)

    # -- structural identity ------------------------------------------

    def test_output_is_plain_dict_json_serializable(self) -> None:
        # Include a REAL IMA violation: the claims go straight to the
        # signer's json.dumps, so non-empty violations must be plain
        # dicts — an empty-violations fixture once hid a FailureEntry
        # leak that broke signing on the common "IMA failed" path.
        failure = Failure(Component.IMA, ["validation", "ima-ng"])
        failure.add_event("not_in_allowlist", {"message": "m"}, True)
        item = _make_item(
            {
                "quote": _build_quote_fixture(),
                "hash_alg": "sha256",
                "ima_measurement_list": _make_ima_list(3),
                "mb_log": _load_mb_log(),
            },
            failure=failure,
            status="fail",
        )
        claims = self.translator.translate(item)
        self.assertIsInstance(claims, dict)
        self.assertEqual(len(claims["ima"]["violations"]), 1)
        # The same structure must survive a JSON round trip unchanged —
        # it feeds both the token payload and the response body.
        self.assertEqual(json.loads(json.dumps(claims)), claims)

    # -- no leaks ------------------------------------------------------

    def test_only_defined_top_level_sections_and_json_types(self) -> None:
        item = _make_item(
            {
                "quote": _build_quote_fixture(),
                "hash_alg": "sha256",
                "ima_measurement_list": _make_ima_list(3),
                "mb_log": _load_mb_log(),
                "tpm_ek": "not-parsed-by-the-translator",
                "tpm_ak": "not-parsed-by-the-translator",
                "nonce": "deadbeef",
            }
        )
        claims = self.translator.translate(item)
        self.assertEqual(sorted(claims.keys()), ["hash_alg", "ima", "measured_boot", "pcrs"])

        def walk(value: Any) -> None:
            self.assertIsInstance(value, (dict, list, str, int, bool, type(None)), f"non-JSON type: {type(value)}")
            if isinstance(value, dict):
                for v in value.values():
                    walk(v)
            elif isinstance(value, list):
                for v in value:
                    walk(v)

        walk(claims)
        # Caller-submitted material the translator must not restate:
        self.assertNotIn("deadbeef", json.dumps(claims))
        self.assertNotIn("not-parsed-by-the-translator", json.dumps(claims))

    # -- Robustness ---------------------------------------------------------

    def test_missing_quote_yields_empty_pcrs(self) -> None:
        claims = self.translator.translate(_make_item({}))
        self.assertEqual(claims["pcrs"], {})

    def test_undecodable_quote_yields_empty_pcrs(self) -> None:
        claims = self.translator.translate(_make_item({"quote": "r!!!:!!!:!!!"}))
        self.assertEqual(claims["pcrs"], {})

    def test_missing_mb_log_yields_empty_section(self) -> None:
        claims = self.translator.translate(_make_item({}))
        self.assertEqual(
            claims["measured_boot"],
            {"entries_count": 0, "pcrs": None, "boot_aggregates": None, "version": None},
        )

    def test_empty_ima_list_yields_zero_count(self) -> None:
        claims = self.translator.translate(_make_item({}))
        self.assertEqual(claims["ima"]["entries_count"], 0)
        self.assertIsNone(claims["ima"]["boot_aggregate"])

    # -- Read-only ----------------------------------------------------------

    def test_translator_does_not_mutate_inputs(self) -> None:
        evidence = {
            "quote": _build_quote_fixture(),
            "hash_alg": "sha256",
            "ima_measurement_list": _make_ima_list(3),
            "mb_log": _load_mb_log(),
        }
        failure = Failure(Component.IMA, ["validation", "ima-ng"])
        failure.add_event("not_in_allowlist", {"message": "m"}, True)
        item = _make_item(copy.deepcopy(evidence), failure=failure, status="fail")

        evidence_snapshot = copy.deepcopy(item.evidence)
        failure_snapshot = copy.deepcopy(item.failure.events)

        self.translator.translate(item)

        self.assertEqual(dict(item.evidence), evidence_snapshot)
        self.assertEqual(
            [(e.event_id, e.context) for e in item.failure.events],
            [(e.event_id, e.context) for e in failure_snapshot],
        )

    # -- measured_boot details ----------------------------------------------

    def test_measured_boot_pcrs_boot_aggregates_version(self) -> None:
        item = _make_item({"mb_log": _load_mb_log(), "hash_alg": "sha256"})
        claims = self.translator.translate(item)
        mb = claims["measured_boot"]
        self.assertIsNotNone(mb["pcrs"])
        for value in mb["pcrs"].values():
            # zero-padded lowercase hex, full sha256 width
            self.assertRegex(value, r"^[0-9a-f]{64}$")
        self.assertIsNotNone(mb["boot_aggregates"])
        self.assertIn("sha256", mb["boot_aggregates"])
        self.assertEqual(mb["version"], 2)
        self.assertIsInstance(mb["version"], int)

    def test_measured_boot_without_hash_alg_degrades_to_nulls(self) -> None:
        # A log without an algorithm must not be replayed against a
        # guessed bank: the values would look real while corresponding
        # to no actual PCR bank (and would disagree with the quote's own
        # PCRs, which use the algorithm embedded in the quote).
        item = _make_item({"mb_log": _load_mb_log()})
        claims = self.translator.translate(item)
        self.assertEqual(
            claims["measured_boot"],
            {"entries_count": 0, "pcrs": None, "boot_aggregates": None, "version": None},
        )

    # -- boot_aggregate ------------------------------------------------------

    def test_ima_boot_aggregate_from_first_entry(self) -> None:
        digest = "e4cb9f5709c88376b5fc3743cd88e76b9aae8f3d992d845678de5215edb31216"
        item = _make_item({"ima_measurement_list": _make_ima_list(4, boot_aggregate=digest)})
        claims = self.translator.translate(item)
        self.assertEqual(claims["ima"]["boot_aggregate"], digest)

    def test_ima_boot_aggregate_absent_list_is_none(self) -> None:
        claims = self.translator.translate(_make_item({}))
        self.assertIsNone(claims["ima"]["boot_aggregate"])

    # -- hash_alg ------------------------------------------------------------

    def test_hash_alg_passthrough(self) -> None:
        claims = self.translator.translate(_make_item({"hash_alg": "sha384"}))
        self.assertEqual(claims["hash_alg"], "sha384")

    def test_hash_alg_absent_is_none(self) -> None:
        claims = self.translator.translate(_make_item({}))
        self.assertIsNone(claims["hash_alg"])

    def test_hash_alg_garbage_is_not_restated(self) -> None:
        # The field is client-influenced and lands in the SIGNED token:
        # unknown or oversized values must be restated as None, never
        # passed through (token-bloat hygiene).
        for garbage in ["x" * 100000, "not-an-algorithm", "sha256; drop table", 42, b"sha256"]:
            with self.subTest(garbage=type(garbage).__name__):
                claims = self.translator.translate(_make_item({"hash_alg": garbage}))
                self.assertIsNone(claims["hash_alg"])
                self.assertNotIn("x" * 100000, json.dumps(claims))
                self.assertNotIn("not-an-algorithm", json.dumps(claims))

    # -- Submitted vs evaluated semantics ------------------------------------

    def test_early_quote_failure_keeps_submitted_count_and_marks_unevaluated(self) -> None:
        # Quote validation failed and returned early, before any PCR/IMA/MB
        # check: the submitted count is still 1234, but the IMA log was
        # never checked — evaluated must be false so the token can never
        # read as "checked and clean".
        failure = Failure(Component.QUOTE_VALIDATION)
        failure.add_event("quote_validation", {"message": "signature mismatch"}, False)
        item = _make_item(
            {"quote": _build_quote_fixture(), "ima_measurement_list": _make_ima_list(1234),
             "runtime_policy": "e30="},
            failure=failure,
            status="fail",
        )
        claims = self.translator.translate(item)
        self.assertEqual(claims["ima"]["entries_count"], 1234)
        self.assertFalse(claims["ima"]["evaluated"])
        self.assertEqual(claims["ima"]["violations"], [])

    def test_recoverable_ima_violation_keeps_evaluated_true(self) -> None:
        # An IMA violation is recoverable: the evaluation COMPLETED, so
        # evaluated stays true while the violations are listed.
        failure = Failure(Component.IMA, ["validation", "ima-ng"])
        failure.add_event("not_in_allowlist", {"message": "file not in allowlist"}, True)
        item = _make_item(
            {"quote": _build_quote_fixture(), "ima_measurement_list": _make_ima_list(10),
             "runtime_policy": "e30="},
            failure=failure,
            status="fail",
        )
        claims = self.translator.translate(item)
        self.assertTrue(claims["ima"]["evaluated"])
        self.assertEqual(len(claims["ima"]["violations"]), 1)

    def test_quote_without_ima_pcr_marks_unevaluated(self) -> None:
        # Passing evaluation whose quote omits PCR 10: IMA is skipped.
        pcrs = {0: b"\x11" * 32, 1: b"\x22" * 32}
        item = _make_item(
            {
                "quote": _build_quote_fixture(pcrs),
                "hash_alg": "sha256",
                "ima_measurement_list": _make_ima_list(10),
                "runtime_policy": "e30=",
            }
        )
        claims = self.translator.translate(item)
        self.assertEqual(claims["ima"]["entries_count"], 10)
        self.assertFalse(claims["ima"]["evaluated"])
        self.assertEqual(claims["ima"]["violations"], [])

    def test_quote_without_ima_list_marks_unevaluated(self) -> None:
        # PCR 10 quoted and a runtime policy present, but no measurement
        # list submitted: the evaluator skips IMA (it logs an
        # unused_pcr_10 event), so evaluated must be false — a policy
        # alone never causes an evaluation.
        item = _make_item(
            {
                "quote": _build_quote_fixture(),
                "hash_alg": "sha256",
                "runtime_policy": "e30=",
            }
        )
        claims = self.translator.translate(item)
        self.assertEqual(claims["ima"]["entries_count"], 0)
        self.assertFalse(claims["ima"]["evaluated"])
        self.assertEqual(claims["ima"]["violations"], [])

    def test_no_runtime_policy_still_evaluates(self) -> None:
        # The evaluator always has a runtime policy (empty by default)
        # and checks IMA whenever PCR 10 is quoted and a list was
        # submitted — so the absence of a runtime policy field must NOT
        # mark the log unevaluated.
        item = _make_item(
            {
                "quote": _build_quote_fixture(),
                "hash_alg": "sha256",
                "ima_measurement_list": _make_ima_list(10),
            }
        )
        claims = self.translator.translate(item)
        self.assertTrue(claims["ima"]["evaluated"])

    def test_full_evaluation_marks_evaluated(self) -> None:
        item = _make_item(
            {
                "quote": _build_quote_fixture(),
                "hash_alg": "sha256",
                "ima_measurement_list": _make_ima_list(10),
                "runtime_policy": "e30=",
            }
        )
        claims = self.translator.translate(item)
        self.assertTrue(claims["ima"]["evaluated"])

    # -- MBA lazy-init guard --------------------------------------------------

    def test_lazy_init_guard_is_noop_when_already_populated(self) -> None:
        # _mba_imports is populated in setUp; translating must not reset
        # or re-append to it.
        before = list(self._mba_module._mba_imports)  # pylint: disable=protected-access
        self.translator.translate(_make_item({"mb_log": _load_mb_log(), "hash_alg": "sha256"}))
        after = list(self._mba_module._mba_imports)  # pylint: disable=protected-access
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
