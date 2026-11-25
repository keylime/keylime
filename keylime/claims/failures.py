"""Normalization of keylime failure events for relying parties.

Keylime's internal failure events speak verifier-internal component ids
and JSON-string contexts; this module maps each event onto a small
external type taxonomy (eval.*, tpm.*, tee.*) so a relying party can
interpret what failed without knowing keylime internals, and bounds the
output so it is safe to embed in a signed token. Degradation (unparsable,
non-object, oversized, unmapped) is never silent — it logs.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from keylime import keylime_logging
from keylime.claims.base import FailureEntry

logger = keylime_logging.init_logging("claims.failures")

MAX_FAILURE_ENTRIES = 100
MAX_FIELD_LEN = 1024
MAX_CONTEXT_BYTES = 4096

# Shape an event-id remainder must have to be substituted into an
# external type (see _map_failure_type's template handling).
_EXTERNAL_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]*")

# Internal (component value, event-id pattern) -> external failure type.
# Component values are keylime.failure.Component values verbatim
# (including the historical "qoute_validation" typo). Patterns are exact
# strings or "<prefix>*"; the most specific match wins. Unmapped pairs
# become the closed "eval.unmapped_failure" (logged, never emitted).
#
# TODO: this central table is a stopgap and should eventually be reworked.
# Reverse-mapping (component, event_id) -> external type here, far from
# where the events are created, has two problems: it drifts silently (a
# new internal event_id falls through to "eval.unmapped_failure" until
# someone remembers to add a row here), and it does not scale to
# out-of-tree plugins (e.g. the upcoming az-snp-vtpm backend, distinct
# from base snp) — a plugin cannot contribute its failure vocabulary
# without patching this core table, and since keylime.failure.Component is
# a closed enum it cannot even emit events under its own identity.
#
# The cleaner fix lives in keylime/failure.py (out of scope here), roughly
# in increasing order of change:
#   1. Self-describing events: let Failure.add_event() carry an explicit
#      external type / stable claim category chosen by the producer (which
#      knows what the failure means), so this layer just reads it and no
#      reverse-mapping table is needed at all.
#   2. Distributed ownership: keep a mapping, but have each component owner
#      register its own {event_id -> external type} rules, co-located with
#      the code that emits the events, instead of this one central dict.
#   3. Open up component identity: make the Event/Failure component a
#      Union[Component, str] (or a small component registry) so a plugin
#      can define and emit events under its own component prefix without
#      editing the core enum — a prerequisite for (1)/(2) to actually
#      serve out-of-tree backends.
FAILURE_TYPE_MAP: Dict[Tuple[str, str], str] = {
    # request/input errors
    ("default", "missing_param"): "eval.missing_param",
    ("default", "missing_policy"): "eval.missing_policy",
    ("internal", "*"): "eval.internal_error",
    # a request field, not quote content:
    ("qoute_validation", "invalid_hash_alg"): "eval.invalid_hash_alg",
    # quote/signature verification
    ("qoute_validation", "*"): "tpm.quote_invalid",
    # PCR allowlist checks
    ("pcr_validation", "invalid_pcr_*"): "tpm.pcr_mismatch",
    ("pcr_validation", "unused_pcr_*"): "tpm.pcr_mismatch",
    ("pcr_validation", "missing_pcrs"): "tpm.pcr_mismatch",
    # measured boot
    ("measured_boot", "*"): "tpm.mb_mismatch",
    # IMA runtime-policy violations (incl. the dm.* table events)
    ("ima", "*"): "tpm.ima_violation",
    # TEE/SEV-SNP: the event detail is preserved. The generic TEE component
    # serves every TEE flavor today, so the external type must not claim a
    # specific one.
    ("tee_attestation", "*"): "tee.<event_id>",
    # TODO: once the failure Component enum grows per-plugin members, key
    # the SNP flavors on their own components (both map to snp.*):
    #   ("snp", "*"): "snp.<event_id>",
    #   ("az_snp_vtpm", "*"): "snp.<event_id>",
}


def normalize_failure(failure: Any) -> List[FailureEntry]:
    """Normalize a Failure object into a bounded list of FailureEntry.

    An empty (or absent) Failure yields []. The list is capped at
    MAX_FAILURE_ENTRIES entries including a terminal "eval.truncated"
    marker when events were dropped.
    """
    if failure is None:
        return []

    events = list(getattr(failure, "events", None) or [])
    entries: List[FailureEntry] = []
    for event in events:
        if len(events) > MAX_FAILURE_ENTRIES and len(entries) >= MAX_FAILURE_ENTRIES - 1:
            # Only truncate when events actually exceed the cap — at
            # exactly MAX events nothing is dropped and no marker is
            # invented. The marker is counted inside the cap.
            omitted = len(events) - len(entries)
            entries.append(
                FailureEntry(
                    type="eval.truncated",
                    message="failure entry list truncated",
                    context={"omitted": omitted},
                )
            )
            return entries
        entries.append(normalize_event(event))
    return entries


def normalize_event(event: Any) -> FailureEntry:
    """Normalize ONE Failure event into a FailureEntry.

    Exposed as a helper so per-section claims (e.g. IMA violations inside
    the attester claims) can reuse the exact same mapping and bounds.
    """
    event_id = getattr(event, "event_id", "")
    component, _, remainder = event_id.partition(".")

    external_type = _map_failure_type(component, remainder)
    if external_type is None:
        logger.warning(
            "No external failure type mapping for internal event id %s; emitting the generic type instead",
            event_id,
        )
        external_type = "eval.unmapped_failure"

    message, context = _extract_message_and_context(event)

    if not message:
        message = external_type
    message = _truncate_str(message)

    return FailureEntry(type=external_type, message=message, context=context)


def _map_failure_type(component: str, remainder: str) -> Optional[str]:
    """Return the external type for a (component, remainder) pair, or None.

    Longest-match-wins: exact remainder beats any prefix, a longer prefix
    beats a shorter one, "*" loses to both.
    """
    best_specificity = -1
    best_external: Optional[str] = None
    for (comp, pattern), external in FAILURE_TYPE_MAP.items():
        if comp != component:
            continue
        if pattern == "*":
            specificity = 0
        elif pattern.endswith("*"):
            prefix = pattern[:-1]
            if not remainder.startswith(prefix):
                continue
            specificity = len(prefix)
        else:
            if remainder != pattern:
                continue
            specificity = len(pattern) + 1
        if specificity > best_specificity:
            best_specificity = specificity
            best_external = external

    if best_external is None:
        return None
    if "<event_id>" in best_external:
        if not _EXTERNAL_ID_RE.fullmatch(remainder):
            # The remainder is substituted into a type field that
            # relying parties switch on; anything but a plain
            # lowercase identifier shape degrades to the generic type
            # rather than risking a future injection sink.
            return None
        best_external = best_external.replace("<event_id>", remainder)
    return best_external


def _extract_message_and_context(event: Any) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Parse an event's JSON-string context into (message, context)."""
    raw = getattr(event, "context", None)
    parsed: Any = None

    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            logger.warning("Unparsable event context on event id %s; dropping the context", getattr(event, "event_id", ""))
            parsed = None
    elif isinstance(raw, dict):
        parsed = dict(raw)

    if parsed is not None and not isinstance(parsed, dict):
        logger.warning(
            "Event context on event id %s is not a JSON object; dropping the context", getattr(event, "event_id", "")
        )
        parsed = None

    message = ""
    context: Optional[Dict[str, Any]] = None
    if isinstance(parsed, dict):
        message = parsed.pop("message", "")
        if not isinstance(message, str) or not message:
            # A non-string or empty message (e.g. an explicit null) must
            # not become a literal "None" in the signed token — treat it
            # as absent; the caller falls back to the external type.
            message = ""
        if parsed:
            context = parsed

    if context is not None:
        # _bound_context logs when it drops the context
        context = _bound_context(context, event_id=getattr(event, "event_id", ""))
    return message, context


def _bound_context(context: Dict[str, Any], event_id: str = "") -> Optional[Dict[str, Any]]:
    """Apply string-length and serialized-size bounds to a context dict.

    Returns None when the serialized context exceeds MAX_CONTEXT_BYTES.
    """
    bounded: Dict[str, Any] = _truncate_strings(context)
    try:
        serialized = json.dumps(bounded)
    except (TypeError, ValueError):
        logger.warning("Non-serializable event context on event id %s; dropping the context", event_id)
        return None
    # Measure bytes, not characters, so the bound survives a future switch
    # to non-ASCII serialization.
    if len(serialized.encode("utf-8")) > MAX_CONTEXT_BYTES:
        logger.warning(
            "Event context on event id %s exceeds %d bytes when serialized; dropping the context",
            event_id,
            MAX_CONTEXT_BYTES,
        )
        return None
    return bounded


def _truncate_strings(value: Any) -> Any:
    """Recursively cap every string at MAX_FIELD_LEN characters.

    Tuples become lists (both serialize to JSON arrays)."""
    if isinstance(value, str):
        return _truncate_str(value)
    if isinstance(value, dict):
        return {k: _truncate_strings(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_truncate_strings(v) for v in value]
    return value


def _truncate_str(value: str) -> str:
    if len(value) <= MAX_FIELD_LEN:
        return value
    return value[:MAX_FIELD_LEN]
