"""TEE/SNP claims translator (skeleton).

Remaps the flat SNP claims of the SEV-SNP TEE plugin into nested
sections via FLAT_TO_NESTED. The Azure vTPM plugin emits a divergent
flat shape (string booleans, base64 measurement, no host_data) — the
table targets the SEV-SNP shape only.

Not a pure key remap: int-list fields (measurement, report_data,
host_data) need hex conversion; guest_svn/report_id/chip_id come from
the raw report bytes. The TEE pubkey arrives via request parameters,
not runtime data.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Tuple

from keylime.claims.base import ClaimsTranslator, EvaluatedEvidence, KeylimeClaimsError
from keylime.claims.registry import register_evidence_type

# flat key -> nested path in the claims output
FLAT_TO_NESTED: Mapping[str, Tuple[str, ...]] = {
    # tcb block:
    "reported_tcb_bootloader": ("tcb", "bootloader"),
    "reported_tcb_tee": ("tcb", "tee"),
    "reported_tcb_snp": ("tcb", "snp"),
    "reported_tcb_microcode": ("tcb", "microcode"),
    # scalar / hex-converted fields:
    "measurement": ("measurement",),
    "report_data": ("evidence_binding", "report_data"),
    "host_data": ("evidence_binding", "host_data"),
    # guest policy flags -> guest_policy object:
    "policy_debug_allowed": ("guest_policy", "debug_allowed"),
    "policy_smt_allowed": ("guest_policy", "smt_allowed"),
    "policy_migrate_ma": ("guest_policy", "migration_agent_allowed"),
    "policy_single_socket": ("guest_policy", "single_socket_required"),
    "policy_abi_major": ("guest_policy", "abi_major"),
    "policy_abi_minor": ("guest_policy", "abi_minor"),
    # platform flags -> platform_info object:
    "platform_smt_enabled": ("platform_info", "smt_enabled"),
    "platform_tsme_enabled": ("platform_info", "tsme_enabled"),
}
# Not in the table — extracted from the raw report, not the flat output:
#   guest_svn, report_id, chip_id


@register_evidence_type
class TeeSnpClaimsTranslator(ClaimsTranslator):
    evidence_type = "tee-snp"

    def translate(self, item: EvaluatedEvidence) -> Dict[str, Any]:
        # TODO: apply FLAT_TO_NESTED to the flat SNP claims output;
        #   guest_policy/platform_info flag splitting per the mapping
        #   table; int-list-to-hex conversion; keylime_tee_pubkey.
        # KeylimeClaimsError (NOT NotImplementedError): this skeleton is
        # REGISTERED, so the pipeline can reach it — it must degrade to
        # the same graceful caller-mapped path as unknown evidence types,
        # not crash with a 500.
        raise KeylimeClaimsError("tee-snp claims translation not yet implemented")
