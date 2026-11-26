"""TPM claims translator: one-shot TPM verification facts -> nested claims.

Sections — pcrs, hash_alg, ima, measured_boot — are always present;
fields are null when not derivable. Facts are verdict-independent and
derived read-only from the evidence block (no verification calls, no
input mutation, JSON-serializable output).

Deliberately deferred (no consumer yet): clock_info (restart counts are
a replay signal, but the right source is the evaluator in continuous
mode) and EK/AK identity fingerprints (the one-shot flow does not bind
the EK to the quote, so a fingerprint would only attest
caller-submitted material).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from keylime import config, keylime_logging
from keylime.claims.base import ClaimsTranslator, EvaluatedEvidence
from keylime.claims.failures import bounded_failure_entries
from keylime.claims.registry import register_evidence_type

logger = keylime_logging.init_logging("claims.translators.tpm")

_IMA_EVENT_PREFIX = "ima."


@register_evidence_type
class TpmClaimsTranslator(ClaimsTranslator):
    """Translates TPM verification facts into nested claims.

    The registry key is the COARSE attestation-source category, NOT the
    request model's granular evidence-type vocabulary (tpm_quote,
    uefi_log, ima_log): one TPM evaluation consumes all three, so a
    passthrough key is impossible. The caller normalizes
    {tpm_quote, uefi_log, ima_log} -> "tpm" when building the
    EvaluatedEvidence.
    """

    evidence_type = "tpm"

    def translate(self, item: EvaluatedEvidence) -> Dict[str, Any]:
        pcrs = self._pcrs(item.evidence)
        return {
            "pcrs": pcrs,
            "hash_alg": self._hash_alg(item.evidence),
            "ima": self._ima(item.evidence, item.failure, pcrs),
            "measured_boot": self._measured_boot(item.evidence),
        }

    @staticmethod
    def _pcrs(evidence: Mapping[str, Any]) -> Dict[str, str]:
        """PCRs quoted in the evidence, keyed by decimal-string index.

        All PCRs present in the quote are reported (lossless and
        policy-independent — the quote attests them regardless of the
        policy mask). Values are lowercase hex, as produced by the quote
        parser.
        """
        quote = evidence.get("quote")
        if not isinstance(quote, str) or not quote:
            return {}
        try:
            # Lazy import: keeps this module importable without pulling in
            # the TPM stack at package import time.
            from keylime.tpm.tpm_main import Tpm  # pylint: disable=import-outside-toplevel

            # compressed=False: the compression flag is a legacy of the
            # agent-version handshake, which has no one-shot equivalent.
            pcrs = Tpm.get_pcrs_from_quote(quote, False)  # type: ignore[no-untyped-call]
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("Could not extract PCRs from the submitted quote: %s", e)
            return {}
        return {str(idx): value for idx, value in pcrs.items()}

    @staticmethod
    def _hash_alg(evidence: Mapping[str, Any]) -> Optional[str]:
        """The request's hash algorithm, restated only when recognized.

        The field is client-influenced and lands in the SIGNED token,
        so an unknown or oversized value is restated as None — never
        passed through verbatim (token-bloat hygiene; the failure
        taxonomy carries the verdict). The quote's signature-blob header
        carries the algorithm too — they must agree for verification to
        pass; the request field is the source here.
        """
        hash_alg = evidence.get("hash_alg")
        if not isinstance(hash_alg, str) or not _is_recognized_hash_alg(hash_alg):
            return None
        return hash_alg

    @staticmethod
    def _ima(evidence: Mapping[str, Any], failure: Any, pcrs: Mapping[str, str]) -> Dict[str, Any]:
        """IMA facts: submitted-log count, boot aggregate, evaluated flag,
        and the evaluator's violations.

        SEMANTICS (submitted vs evaluated — critical for a truthful
        token): ``entries_count`` counts entries in the SUBMITTED log;
        ``violations`` lists violations the EVALUATOR found. These are
        different things and must never be conflated: the verification
        flow returns early on quote-validation failure and skips IMA
        entirely when the IMA PCR is not in the quote or no measurement
        list was submitted — in both cases the log was never checked,
        yet ``entries_count`` is still the submitted line count,
        ``evaluated`` is false, and ``violations`` is empty BECAUSE
        nothing was checked. A relying party can never misread "not
        checked" as "checked and clean". ``evaluated`` mirrors the
        evaluator's own gate (PCR 10 quoted + list submitted + not
        short-circuited); the evaluator always has a runtime policy
        (empty by default), so the policy is not part of the condition.
        """
        ima_list = evidence.get("ima_measurement_list")
        # The evaluator's gate treats ANY string (including the empty
        # "no new events" submission) as a list that gets checked, and
        # everything else as no list at all — so evaluated must use a
        # TYPE check, not truthiness, and must not read the sanitized
        # value (a non-string must never read as "checked and clean").
        raw_ima_list = ima_list
        if not isinstance(ima_list, str):
            ima_list = ""
        lines = [line for line in ima_list.splitlines() if line]
        entries_count = len(lines)
        first_line = lines[0] if lines else None

        # An irrecoverable event means the verification flow returned
        # early and might have skipped the later checks (that is the
        # documented meaning of the flag on the Failure object) — on the
        # one-shot path exactly the quote-validation failures mark it.
        short_circuited = any(
            not getattr(event, "recoverable", True) for event in (getattr(failure, "events", None) or [])
        )
        # Mirrors the evaluator's own IMA gate (config.IMA_PCR, the IMA
        # PCR the verifier checks) — a constant, not ambient config.
        evaluated = str(config.IMA_PCR) in pcrs and isinstance(raw_ima_list, str) and not short_circuited

        return {
            "entries_count": entries_count,
            "evaluated": evaluated,
            "violations": TpmClaimsTranslator._ima_violations(failure),
            "boot_aggregate": TpmClaimsTranslator._boot_aggregate(first_line),
        }

    @staticmethod
    def _ima_violations(failure: Any) -> List[Dict[str, Any]]:
        """Failure events caused by the IMA check, as plain dicts.

        Filtered by the INTERNAL event-id prefix "ima." — the real ids
        are stable regardless of external naming decisions. The
        matching events go through the same normalization (mapping +
        bounds + entry cap) as the general failure list, then are
        emitted as {type, message, context} — the same wire shape as
        keylime_failures, and plain JSON-serializable types as the
        translator contract requires (the claims go straight to the
        signer's json.dumps).
        """
        events = [
            event
            for event in (getattr(failure, "events", None) or [])
            if getattr(event, "event_id", "").startswith(_IMA_EVENT_PREFIX)
        ]
        return [
            {"type": entry.type, "message": entry.message, "context": entry.context}
            for entry in bounded_failure_entries(events)
        ]

    @staticmethod
    def _boot_aggregate(first_line: Optional[str]) -> Optional[str]:
        """Digest of the first (boot-aggregate) entry of the measurement list.

        None when the list is absent or the first entry is unparsable or
        is not a boot_aggregate entry.
        """
        if first_line is None:
            return None
        try:
            # Lazy import: keeps this module importable without the IMA
            # parser stack at package import time.
            from keylime.ima import ast  # pylint: disable=import-outside-toplevel

            entry = ast.Entry(first_line)
            mode = entry.mode
            if not isinstance(mode, (ast.Ima, ast.ImaNg, ast.ImaSig)):
                return None
            if mode.path.name != "boot_aggregate":
                return None
            return str(mode.digest.hash.hex())
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("Could not parse the first IMA measurement list entry: %s", e)
            return None

    @staticmethod
    def _measured_boot(evidence: Mapping[str, Any]) -> Dict[str, Any]:
        """Measured-boot facts replayed from the submitted log.

        The parser is initialized LAZILY here (never at import time):
        seeding the parser list at module import would pre-load the
        default parsers, and the verifier's own startup initialization
        would then APPEND the operator's custom measured-boot policies
        AFTER them — first-match resolution would silently ignore the
        custom policies. With the lazy guard, a running verifier (already
        initialized at startup) is unaffected, and standalone users get
        the default parsers exactly once.
        """
        empty = {"entries_count": 0, "pcrs": None, "boot_aggregates": None, "version": None}
        mb_log = evidence.get("mb_log")
        if not isinstance(mb_log, str) or not mb_log:
            return dict(empty)

        hash_alg = evidence.get("hash_alg")
        if not isinstance(hash_alg, str) or not _is_recognized_hash_alg(hash_alg):
            # No (recognized) algorithm → no replay: guessing one (e.g.
            # sha256) would produce real-looking PCR values in a bank
            # that may not exist, disagreeing with the quote's own PCRs.
            # Fields stay null ("null when not derivable"); same gate as
            # the hash_alg claim itself.
            return dict(empty)

        try:
            # Lazy import: the module path is the INNER module (the mba
            # package __init__ is empty).
            from keylime.mba import mba as mba_module  # pylint: disable=import-outside-toplevel

            if not mba_module._mba_imports:  # pylint: disable=protected-access
                logger.warning("Measured-boot parsers not initialized in this process; loading the default parsers")
                mba_module.load_imports(skip_custom_policies=True)

            mb_pcrs_hashes, boot_aggregates, mb_data, _mb_failure = mba_module.bootlog_parse(mb_log, hash_alg)

            # Everything derived from the parsed log stays INSIDE this
            # guarded block: the values come from attacker-submitted log
            # content, and a weird shape (e.g. a non-integer PCR value)
            # must degrade to the empty section — never raise out of
            # translate(), which would turn a "fail" verdict into an
            # infrastructure "error" and suppress the token.
            if not mb_data:
                # A base64-decodable but invalid log parses to an empty
                # dict without raising; degrade the same way.
                return dict(empty)

            pcrs = None
            if mb_pcrs_hashes:
                # The parser returns the replayed PCR values as large
                # INTEGERS; convert to lowercase hex strings ZERO-PADDED
                # to the hash width (a plain hex format drops leading
                # zero bytes and breaks value comparison against the
                # quoted PCRs).
                width = _hash_hex_width(hash_alg)
                pcrs = {str(idx): f"{value:0{width}x}" for idx, value in mb_pcrs_hashes.items()}

            events = mb_data.get("events")
            return {
                "entries_count": len(events) if isinstance(events, (list, tuple)) else 0,
                "pcrs": pcrs,
                "boot_aggregates": boot_aggregates,
                "version": mb_data.get("version"),
            }
        except Exception as e:  # pylint: disable=broad-exception-caught
            # bootlog_parse wraps ALL parser failures (not just bad
            # base64) as ValueError; log and degrade — the failure events
            # carry the verdict.
            logger.warning("Could not parse the measured-boot log: %s", e)
            return dict(empty)


def _is_recognized_hash_alg(hash_alg: str) -> bool:
    """Whether the algorithm name is one of keylime's known hash algorithms."""
    try:
        from keylime.common.algorithms import Hash  # pylint: disable=import-outside-toplevel

        return Hash.is_recognized(hash_alg)
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _hash_hex_width(hash_alg: str) -> int:
    """Hex-character width of a hash algorithm name (fallback: sha256)."""
    try:
        from keylime.common.algorithms import Hash  # pylint: disable=import-outside-toplevel

        return Hash(hash_alg).get_hex_size()
    except Exception:  # pylint: disable=broad-exception-caught
        return 64
