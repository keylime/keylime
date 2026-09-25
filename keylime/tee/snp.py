import hashlib
from typing import Any, Tuple

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from keylime.failure import Component, Failure


# Verify that a SEV-SNP attestation report is verified by a VEK.
def verify_attestation(
    report: bytes, nonce: bytes, tee_pubkey_x: bytes, tee_pubkey_y: bytes
) -> Tuple[dict[str, Any], Failure]:
    failure = Failure(Component.TEE)

    if len(report) < 0x188:
        failure.add_event(
            "invalid_input",
            {"message": "SEV-SNP attestation report input invalid"},
            False,
        )
        return ({}, failure)

    verified = vek_signature_verify(report, failure)
    if verified is False:
        return ({}, failure)

    fresh = nonce_pubkey_freshness_verify(report, nonce, tee_pubkey_x, tee_pubkey_y, failure)
    if fresh is False:
        return ({}, failure)

    claims = sev_snp_claims(report)

    return (claims, failure)


def get_processor_model(report: bytes) -> str:
    """
    Determine the AMD processor model from the SEV-SNP attestation report.

    The report VERSION field and CHIP_ID help identify the processor generation.
    Returns the processor model name for use in the AMD KDS VCEK URL.
    """
    version = int.from_bytes(report[0x000:0x004], byteorder="little")
    chip_id_prefix = report[0x1A0:0x1A4]

    # Map attestation report version to processor model
    # Based on AMD SEV-SNP specification revisions
    # Version 1: Milan (Zen 3)
    # Version 2: Genoa, Bergamo, Siena (Zen 4 variants)
    # Version 3+: Turin and future (Zen 5+)

    if version == 1:
        return "Milan"
    elif version == 2:
        # Genoa, Bergamo, and Siena all use version 2
        # These models all work with "Genoa" in the KDS URL path
        # (Bergamo and Siena are Genoa derivatives)
        return "Genoa"
    elif version >= 3:
        # Turin and future processors
        return "Turin"
    else:
        # Unknown version - default to Milan for backwards compatibility
        return "Milan"


def vek_signature_verify(report: bytes, failure: Failure) -> bool:
    reported_tcb = report[0x180:0x188]

    hw_id = report[0x1A0:0x1E0].hex()
    bl = str(reported_tcb[0]).zfill(2)
    tee = str(reported_tcb[1]).zfill(2)
    snp = str(reported_tcb[6]).zfill(2)
    ucode = str(reported_tcb[7]).zfill(2)

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

    sig = report[0x2A0:0x49F]
    r = int.from_bytes(sig[:0x48], byteorder="little")
    s = int.from_bytes(sig[0x48:0x90], byteorder="little")

    sig = encode_dss_signature(r, s)

    if not isinstance(pk, ec.EllipticCurvePublicKey):
        failure.add_event(
            "invalid_public_key",
            {"message": "VEK public key is not an RSA public key"},
            False,
        )
        return False

    try:
        pk.verify(signature=sig, data=report[:0x2A0], signature_algorithm=ec.ECDSA(hashes.SHA384()))
    except InvalidSignature as _:
        failure.add_event(
            "invalid_signature",
            {"message": "VEK public key does not sign SEV-SNP attestation report"},
            False,
        )
        return False

    return True


def nonce_pubkey_freshness_verify(
    report: bytes, nonce: bytes, tee_pubkey_x: bytes, tee_pubkey_y: bytes, failure: Failure
) -> bool:
    sha512 = hashlib.sha512()

    sha512.update(tee_pubkey_x)
    sha512.update(tee_pubkey_y)
    sha512.update(nonce)

    digest = sha512.digest()
    report_data = report[0x50:0x90]

    if digest != report_data:
        failure.add_event(
            "freshness_hash_failed",
            {"message": "REPORT_DATA freshness hash incorrect"},
            False,
        )
        return False

    return True


def sev_snp_claims(report: bytes) -> dict[str, Any]:
    claims: dict[str, Any] = {}

    measurement = list(report[0x90:0xC0])
    report_data = list(report[0x50:0x90])
    host_data = list(report[0xC0:0xE0])

    platform_info = int.from_bytes(report[0x40:0x41], "little")
    smt_enabled = bool(platform_info & (1 << 0))
    tsme_enabled = bool(platform_info & (1 << 1))

    reported_tcb_bootloader = int.from_bytes(report[0x180:0x181], "little")
    reported_tcb_tee = int.from_bytes(report[0x181:0x182], "little")
    reported_tcb_snp = int.from_bytes(report[0x186:0x187], "little")
    reported_tcb_microcode = int.from_bytes(report[0x187:0x188], "little")

    policy = int.from_bytes(report[0x8:0x10], "little")
    policy_abi_minor = int.from_bytes(report[0x8:0x9], "little")
    policy_abi_major = int.from_bytes(report[0x9:0xA], "little")
    policy_smt_allowed = bool(policy & (1 << 16))
    policy_migrate_ma = bool(policy & (1 << 18))
    policy_debug_allowed = bool(policy & (1 << 19))
    policy_single_socket = bool(policy & (1 << 20))

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
