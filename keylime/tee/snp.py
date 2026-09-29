import hashlib
from dataclasses import dataclass
from typing import Any, Tuple

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from keylime.failure import Component, Failure


@dataclass
class SevSnpAttestationReport:
    """
    SEV-SNP Attestation Report structure as defined in the AMD SEV-SNP specification.

    All fields correspond to the documented AMD SEV-SNP attestation report format.
    Offsets are preserved in comments for reference.
    """

    # 0x000: Report version
    version: int

    # 0x004: Guest security version number
    guest_svn: int

    # 0x008: Guest policy
    policy: int

    # 0x010: Family ID
    family_id: bytes

    # 0x020: Image ID
    image_id: bytes

    # 0x030: VMPL level
    vmpl: int

    # 0x034: Signature algorithm
    signature_algo: int

    # 0x038: Platform version
    current_tcb: bytes

    # 0x040: Platform info flags
    platform_info: int

    # 0x048: Author key digest exists flag
    author_key_en: int

    # 0x050: Report data (64 bytes)
    report_data: bytes

    # 0x090: Measurement (48 bytes)
    measurement: bytes

    # 0x0C0: Host data (32 bytes)
    host_data: bytes

    # 0x0E0: ID key digest
    id_key_digest: bytes

    # 0x110: Author key digest
    author_key_digest: bytes

    # 0x140: Report ID
    report_id: bytes

    # 0x160: Report ID MA
    report_id_ma: bytes

    # 0x180: Reported TCB version
    reported_tcb: bytes

    # 0x1A0: Chip ID (64 bytes)
    chip_id: bytes

    # 0x1E0: Committed TCB version
    committed_tcb: bytes

    # 0x1E8: Current build
    current_build: int

    # 0x1EC: Current minor
    current_minor: int

    # 0x1F0: Current major
    current_major: int

    # 0x1F4: Committed build
    committed_build: int

    # 0x1F8: Committed minor
    committed_minor: int

    # 0x1FC: Committed major
    committed_major: int

    # 0x200: Launch TCB version
    launch_tcb: bytes

    # 0x2A0: Signature (512 bytes)
    signature: bytes

    # Raw bytes for signature verification
    raw_bytes: bytes


def parse_attestation_report(report: bytes) -> SevSnpAttestationReport:
    """
    Parse raw bytes into a structured SEV-SNP attestation report.

    Args:
        report: Raw attestation report bytes (minimum 0x4A0 bytes)

    Returns:
        SevSnpAttestationReport object with all fields populated

    Raises:
        ValueError: If report is too short
    """
    if len(report) < 0x4A0:
        raise ValueError(f"Attestation report too short: {len(report)} bytes, expected at least 0x4A0")

    return SevSnpAttestationReport(
        version=int.from_bytes(report[0x000:0x004], byteorder="little"),
        guest_svn=int.from_bytes(report[0x004:0x008], byteorder="little"),
        policy=int.from_bytes(report[0x008:0x010], byteorder="little"),
        family_id=report[0x010:0x020],
        image_id=report[0x020:0x030],
        vmpl=int.from_bytes(report[0x030:0x034], byteorder="little"),
        signature_algo=int.from_bytes(report[0x034:0x038], byteorder="little"),
        current_tcb=report[0x038:0x040],
        platform_info=int.from_bytes(report[0x040:0x048], byteorder="little"),
        author_key_en=int.from_bytes(report[0x048:0x04C], byteorder="little"),
        report_data=report[0x050:0x090],
        measurement=report[0x090:0x0C0],
        host_data=report[0x0C0:0x0E0],
        id_key_digest=report[0x0E0:0x110],
        author_key_digest=report[0x110:0x140],
        report_id=report[0x140:0x160],
        report_id_ma=report[0x160:0x180],
        reported_tcb=report[0x180:0x188],
        chip_id=report[0x1A0:0x1E0],
        committed_tcb=report[0x1E0:0x1E8],
        current_build=int.from_bytes(report[0x1E8:0x1EC], byteorder="little"),
        current_minor=int.from_bytes(report[0x1EC:0x1F0], byteorder="little"),
        current_major=int.from_bytes(report[0x1F0:0x1F4], byteorder="little"),
        committed_build=int.from_bytes(report[0x1F4:0x1F8], byteorder="little"),
        committed_minor=int.from_bytes(report[0x1F8:0x1FC], byteorder="little"),
        committed_major=int.from_bytes(report[0x1FC:0x200], byteorder="little"),
        launch_tcb=report[0x200:0x208],
        signature=report[0x2A0:0x4A0],
        raw_bytes=report,
    )


# Verify that a SEV-SNP attestation report is verified by a VEK.
def verify_attestation(
    report: bytes, nonce: bytes, tee_pubkey_x: bytes, tee_pubkey_y: bytes
) -> Tuple[dict[str, Any], Failure]:
    failure = Failure(Component.TEE)

    if len(report) < 0x4A0:
        failure.add_event(
            "invalid_input",
            {"message": "SEV-SNP attestation report input invalid"},
            False,
        )
        return ({}, failure)

    try:
        parsed_report = parse_attestation_report(report)
    except ValueError as e:
        failure.add_event(
            "parse_error",
            {"message": f"Failed to parse attestation report: {str(e)}"},
            False,
        )
        return ({}, failure)

    verified = vek_signature_verify(parsed_report, failure)
    if verified is False:
        return ({}, failure)

    fresh = nonce_pubkey_freshness_verify(parsed_report, nonce, tee_pubkey_x, tee_pubkey_y, failure)
    if fresh is False:
        return ({}, failure)

    claims = sev_snp_claims(parsed_report)

    return (claims, failure)


def get_processor_model(report: SevSnpAttestationReport) -> str:
    """
    Determine the AMD processor model from the SEV-SNP attestation report.

    The report VERSION field and CHIP_ID help identify the processor generation.
    Returns the processor model name for use in the AMD KDS VCEK URL.
    """
    # Map attestation report version to processor model
    # Based on AMD SEV-SNP specification revisions
    # Version 1: Milan (Zen 3)
    # Version 2: Genoa, Bergamo, Siena (Zen 4 variants)
    # Version 3+: Turin and future (Zen 5+)

    if report.version == 1:
        return "Milan"
    if report.version == 2:
        # Genoa, Bergamo, and Siena all use version 2
        # These models all work with "Genoa" in the KDS URL path
        # (Bergamo and Siena are Genoa derivatives)
        return "Genoa"
    if report.version >= 3:
        # Turin and future processors
        return "Turin"

    # Unknown version - default to Milan for backwards compatibility
    return "Milan"


def vek_signature_verify(report: SevSnpAttestationReport, failure: Failure) -> bool:
    hw_id = report.chip_id.hex()
    bl = str(report.reported_tcb[0]).zfill(2)
    tee = str(report.reported_tcb[1]).zfill(2)
    snp = str(report.reported_tcb[6]).zfill(2)
    ucode = str(report.reported_tcb[7]).zfill(2)

    # Detect processor model from attestation report
    processor_model = get_processor_model(report)

    vcek_url = "https://kdsintf.amd.com/vcek/v1/"
    vcek_url += f"{processor_model}/"
    vcek_url += hw_id + "?"
    vcek_url += "blSPL=" + bl
    vcek_url += "&teeSPL=" + tee
    vcek_url += "&snpSPL=" + snp
    vcek_url += "&ucodeSPL=" + ucode

    res = requests.get(vcek_url, timeout=60)
    if res.status_code != 200:
        failure.add_event(
            "vcek_fetch",
            {
                "message": "unable to fetch VCEK for SEV-SNP report",
                "status_code": res.status_code,
                "processor_model": processor_model,
                "vcek_url": vcek_url,
            },
            False,
        )
        return False

    vcek_x509 = x509.load_der_x509_certificate(res.content, default_backend())
    pk = vcek_x509.public_key()

    # Extract signature components (r, s) from the signature field
    r = int.from_bytes(report.signature[:0x48], byteorder="little")
    s = int.from_bytes(report.signature[0x48:0x90], byteorder="little")

    sig = encode_dss_signature(r, s)

    if not isinstance(pk, ec.EllipticCurvePublicKey):
        failure.add_event(
            "invalid_public_key",
            {"message": "VEK public key is not an RSA public key"},
            False,
        )
        return False

    try:
        pk.verify(signature=sig, data=report.raw_bytes[:0x2A0], signature_algorithm=ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as _:
        failure.add_event(
            "invalid_signature",
            {"message": "VEK public key does not sign SEV-SNP attestation report"},
            False,
        )
        return False

    return True


def nonce_pubkey_freshness_verify(
    report: SevSnpAttestationReport, nonce: bytes, tee_pubkey_x: bytes, tee_pubkey_y: bytes, failure: Failure
) -> bool:
    sha512 = hashlib.sha512()

    sha512.update(tee_pubkey_x)
    sha512.update(tee_pubkey_y)
    sha512.update(nonce)

    digest = sha512.digest()

    if digest != report.report_data:
        failure.add_event(
            "freshness_hash_failed",
            {"message": "REPORT_DATA freshness hash incorrect"},
            False,
        )
        return False

    return True


def sev_snp_claims(report: SevSnpAttestationReport) -> dict[str, Any]:
    claims: dict[str, Any] = {}

    measurement = list(report.measurement)
    report_data = list(report.report_data)
    host_data = list(report.host_data)

    smt_enabled = bool(report.platform_info & (1 << 0))
    tsme_enabled = bool(report.platform_info & (1 << 1))

    reported_tcb_bootloader = report.reported_tcb[0]
    reported_tcb_tee = report.reported_tcb[1]
    reported_tcb_snp = report.reported_tcb[6]
    reported_tcb_microcode = report.reported_tcb[7]

    policy_abi_minor = report.policy & 0xFF
    policy_abi_major = (report.policy >> 8) & 0xFF
    policy_smt_allowed = bool(report.policy & (1 << 16))
    policy_migrate_ma = bool(report.policy & (1 << 18))
    policy_debug_allowed = bool(report.policy & (1 << 19))
    policy_single_socket = bool(report.policy & (1 << 20))

    claims["measurement"] = measurement
    claims["report_data"] = report_data
    claims["host_data"] = host_data
    claims["platform_smt_enabled"] = smt_enabled
    claims["platform_tsme_enabled"] = tsme_enabled
    claims["reported_tcb_bootloader"] = reported_tcb_bootloader
    claims["reported_tcb_tee"] = reported_tcb_tee
    claims["reported_tcb_snp"] = reported_tcb_snp
    claims["reported_tcb_microcode"] = reported_tcb_microcode
    claims["policy_abi_major"] = policy_abi_major
    claims["policy_abi_minor"] = policy_abi_minor
    claims["policy_smt_allowed"] = policy_smt_allowed
    claims["policy_migrate_ma"] = policy_migrate_ma
    claims["policy_debug_allowed"] = policy_debug_allowed
    claims["policy_single_socket"] = policy_single_socket

    return claims
