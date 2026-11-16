"""Azure CVM SEV-SNP + vTPM (az-snp-vtpm) TEE evidence verifier.

Verifies the composite attestation evidence produced by guest-components'
``AzSnpVtpmAttester`` on Azure confidential VMs: a vTPM TPM 2.0 quote over
the guest's measured state, wrapped together with the Azure HCL report
(which contains the AMD SEV-SNP attestation report and the HCL runtime
claims holding the vTPM attestation key) and the VCEK certificate.

The AMD ASK/ARK anchor chains are resolved from a local trust store:
the per-generation PEMs bundled with the package
(keylime/tee/amd_cert_store, see its README for provenance), or the
store configured with the [verifier] amd_anchor_path option. The
default path never touches the network; fetch_kds_chain() exists to
provision or refresh a store (see the README). A generation missing
from the store is simply unavailable and its evidence fails closed.
TODO: add a CI canary that fetches the current chains from the AMD
KDS and diffs them against the bundled ones, alerting on rotation or
staleness; alert-only (it must never update the store, as the KDS
cannot authenticate itself) and network-opt-in for offline CI runs.

TODO: reuse keylime's existing TPMS_ATTEST implementation
(keylime/tpm/tpm2_objects.py unmarshal_tpms_attest) instead of the
plugin's own parse_tpm_attest(); it would need improvements first
(return the pcrSelect banks, bounds-check the length prefixes,
enforce exact consumption, raise ValueError instead of Exception),
but for now the self-contained parser is okay -- refactor later.
TODO: cc_eventlog (AAEL, TCG2 format) carried in v2+ evidence is not
parsed or replayed against the quoted PCRs (DRTM PCRs 17-22 seed from
0xFF*32, others from zero).
TODO: generalize the KDS fetch into a repo-wide certificate
cache-and-fetch mechanism shared by the TEE verifiers (snp.py's
per-attestation VCEK fetch could reuse it); this implementation is
intentionally self-contained.

Note: the in-memory anchor cache is not thread-safe; concurrent
cold-start verifications may race and each load the store once (a
local file read, so this is benign).
"""

import base64
import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from keylime import config, keylime_logging
from keylime.failure import Component, Failure

logger = keylime_logging.init_logging("az_snp_vtpm")

# HCL container (Azure attestation report) layout, all u32 little-endian
HCL_HEADER_SIZE = 32
HCL_HEADER_MAGIC = 0x414C4348  # "HCLA"
# the AMD SEV-SNP attestation report is nested inside the HCL report,
# right after the header
SNP_REPORT_OFFSET = HCL_HEADER_SIZE
SNP_REPORT_SIZE = 1184
# the runtime data area starts right after the SNP report
HCL_RUNTIME_DATA_OFFSET = SNP_REPORT_OFFSET + SNP_REPORT_SIZE
# runtime data header: data_size, version, report_type, hash_type, claim_size (u32 each)
HCL_RUNTIME_DATA_HEADER_SIZE = 20
# HCL header request type: Azure-specific usage of the attestation report
HCL_HEADER_REQUEST_TYPE_SEV_SNP = 2
# runtime data format version (version 1 per the Azure attestation report format)
HCL_RUNTIME_DATA_VERSION = 1
# runtime data report type: the type of the nested hardware report
# (2 = AMD SEV-SNP, 4 = Intel TDX)
HCL_RUNTIME_DATA_REPORT_TYPE_SEV_SNP = 2
# hash type used to commit the claims into the SNP report_data
# (IgvmRequestData.report_data_hash_type); the three values are defined by
# the Azure attestation report format
HCL_RUNTIME_DATA_HASH_TYPE_SHA256 = 1
HCL_RUNTIME_DATA_HASH_TYPE_SHA384 = 2
HCL_RUNTIME_DATA_HASH_TYPE_SHA512 = 3

_RUNTIME_DATA_HASHES = {
    HCL_RUNTIME_DATA_HASH_TYPE_SHA256: hashlib.sha256,
    HCL_RUNTIME_DATA_HASH_TYPE_SHA384: hashlib.sha384,
    HCL_RUNTIME_DATA_HASH_TYPE_SHA512: hashlib.sha512,
}

# AMD SEV-SNP attestation report layout (offsets within the SNP report)
SNP_REPORT_SIGNATURE_OFFSET = 0x2A0
SNP_REPORT_SIGNATURE_R_SIZE = 72  # 72-byte stride per scalar, 48-byte value
SNP_REPORT_POLICY_OFFSET = 0x08
SNP_REPORT_VMPL_OFFSET = 0x30
SNP_REPORT_PLATFORM_INFO_OFFSET = 0x40
SNP_REPORT_REPORT_DATA_OFFSET = 0x50
SNP_REPORT_MEASUREMENT_OFFSET = 0x90
SNP_REPORT_HOST_DATA_OFFSET = 0xC0
SNP_REPORT_REPORTED_TCB_OFFSET = 0x180
SNP_REPORT_CHIP_ID_OFFSET = 0x1A0
SNP_REPORT_CPUID_FAMILY_OFFSET = 0x188
SNP_REPORT_CPUID_MODEL_OFFSET = 0x189
SNP_REPORT_KEY_INFO_OFFSET = 0x48
SNP_SIGNING_KEY_VCEK = 0
SNP_SIGNING_KEY_VLEK = 1

# CPUID family/model of the report (v3+ reports only). Family 0x19 covers
# Milan (EPYC 7003, models < 0x10) and Genoa (EPYC 9004, models >= 0x10);
# family 0x1A is Turin. v2 reports carry no CPUID (the region is reserved)
# and are rejected in _report_generation().
SNP_CPUID_FAMILY_MILAN_GENOA = 0x19
SNP_CPUID_FAMILY_TURIN = 0x1A
SNP_CPUID_GENOA_MIN_MODEL = 0x10

# TPMS_ATTEST constants
TPM_GENERATED = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_SHA256 = 0x000B
EXPECTED_PCR_COUNT = 24
PCR_SIZE = 32

# vTPM measured register semantics (TCG PC Client Firmware Profile)
INIT_DATA_PCR = 8

# AMD KDS certificate custom extension OIDs, as defined by AMD in the SEV-SNP
# Key Distribution Service API spec (#57230): 1.3.6.1.4.1.3704 is AMD's
# IANA-registered private enterprise arc, under which the KDS numbers the
# extensions it writes into the VCEK certificates. The field
# sizes (64-byte chip id, one-byte TCB levels) come from the AMD SEV-SNP
# firmware ABI spec (#56860). These are published vendor identifiers: new
# OIDs may be added for new generations (e.g. FMC for Turin), but existing
# ones do not change.
HW_ID_OID = "1.3.6.1.4.1.3704.1.4"
LOADER_SPL_OID = "1.3.6.1.4.1.3704.1.3.1"
TEE_SPL_OID = "1.3.6.1.4.1.3704.1.3.2"
SNP_SPL_OID = "1.3.6.1.4.1.3704.1.3.3"
FMC_SPL_OID = "1.3.6.1.4.1.3704.1.3.9"
UCODE_SPL_OID = "1.3.6.1.4.1.3704.1.3.8"

# The SNP report must be issued at VMPL 0 (the HCL/paravisor); guest code
# runs at a higher VMPL and can never produce a VMPL-0 report
SNP_REPORT_REQUIRED_VMPL = 0

# Processor generations supported by the AMD trust anchors
PROCESSOR_GENERATIONS = ("milan", "genoa", "turin")

# AMD Key Distribution Service: per-generation ASK/ARK certificate chains
# (verified live: HTTP 200, application/octet-stream, PEM with ASK first,
# ARK second). Only used by fetch_kds_chain() to provision or refresh a
# local trust store; the verification path never fetches from here.
KDS_CERT_CHAIN_URL = "https://kdsintf.amd.com/vcek/v1/{generation}/cert_chain"
KDS_FETCH_TIMEOUT = 10  # seconds

# Per-generation ASK/ARK chains shipped with the package; the default
# trust store (see amd_cert_store/README.md for provenance and refresh
# instructions)
BUNDLED_ANCHOR_STORE = os.path.join(os.path.dirname(__file__), "amd_cert_store")

# In-memory anchor cache, populated by resolve_trust_anchors(); lives for
# the process lifetime (the chains are stable vendor certificates)
_ANCHOR_CACHE: Dict[str, Tuple[x509.Certificate, x509.Certificate]] = {}


@dataclass
class Evidence:
    """Version-normalized az-snp-vtpm attestation evidence."""

    version: int
    quote_message: bytes
    quote_signature: bytes
    # from the tpm_quote object; only their digest is signed (bound to the
    # quote in phase 3), the values themselves are not
    quote_pcrs: List[bytes]
    hcl_report: bytes
    vcek: x509.Certificate
    cc_eventlog: Optional[bytes] = None


@dataclass
class TpmAttest:
    """Fields of interest parsed out of the TPMS_ATTEST quote message."""

    extra_data: bytes
    pcr_digest: bytes
    pcr_select_hash_algs: List[int] = field(default_factory=list)
    pcr_select_bitmap: bytes = b""


@dataclass
class HclReportHeader:
    """The Azure HCL container header (not endorsed by the hardware report)."""

    version: int
    report_size: int
    request_type: int
    status: int


@dataclass
class HclRuntimeData:
    """The runtime data area of the HCL container (IgvmRequestData + claims)."""

    data_size: int
    version: int
    report_type: int
    hash_type: int
    claim_size: int
    claims_bytes: bytes


@dataclass
class HclReport:
    """Parsed Azure HCL (attestation report) container."""

    raw: bytes
    snp_report: bytes
    claims_bytes: bytes
    # hash type the claims are committed with into the SNP report_data
    # (one of HCL_RUNTIME_DATA_HASH_*); used by the phase-4 binding
    hash_type: int
    # kept for future use (e.g. surfacing vm-configuration claims); the
    # verification phases only read claims_bytes, ak_pub and user_data
    claims: Dict[str, Any]
    ak_pub: rsa.RSAPublicKey
    user_data: Optional[bytes]


@dataclass
class SnpReport:
    """Fields of interest parsed out of the nested AMD SNP report."""

    raw: bytes
    policy: int
    vmpl: int
    platform_info: int
    report_data: bytes
    measurement: bytes
    host_data: bytes
    reported_tcb: bytes
    chip_id: bytes
    # processor generation derived from the report's CPUID (v3+) and the
    # generation-aware decoded TCB components (see _decode_tcb)
    generation: str
    tcb_fmc: Optional[int]
    tcb_bootloader: int
    tcb_tee: int
    tcb_snp: int
    tcb_microcode: int


def _b64_decode_nopad(data: str) -> bytes:
    """Base64-decode a urlsafe string, ignoring missing padding.

    Invalid (non-alphabet) characters are rejected rather than silently
    discarded.
    """
    if not isinstance(data, str):
        raise ValueError(f"expected a base64 string, got {type(data).__name__}")
    data = data.strip()
    pad = "=" * (-len(data) % 4)
    # urlsafe_b64decode() has no validate= parameter; strict decoding with
    # the urlsafe alphabet goes through b64decode(altchars="-_")
    return base64.b64decode(data + pad, altchars="-_", validate=True)


def _decode_byte_array(value: Any) -> bytes:
    """Decode a JSON byte array (list of ints 0-255) into bytes."""
    if not isinstance(value, list) or not all(
        isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in value
    ):
        raise ValueError("expected a byte array (list of integers 0-255)")
    return bytes(value)


def _load_x509_certificate(data: bytes, pem: bool = False) -> x509.Certificate:
    """Load one X.509 certificate, converting any failure into ValueError.

    Certificate loading can raise exceptions that are not ValueError
    subclasses (e.g. x509.InvalidVersion for an unsupported version
    INTEGER, UnsupportedAlgorithm for an unknown public key algorithm);
    the evidence parsers rely on ValueError for fail-closed handling.
    """
    try:
        if pem:
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except Exception as e:  # pylint: disable=broad-exception-caught
        raise ValueError(f"invalid X.509 certificate: {e}") from e


def _load_x509_bundle(data: bytes) -> List[x509.Certificate]:
    """Load a PEM certificate bundle, converting any failure into ValueError."""
    try:
        return x509.load_pem_x509_certificates(data)
    except Exception as e:  # pylint: disable=broad-exception-caught
        raise ValueError(f"invalid X.509 certificate bundle: {e}") from e


# ---------------------------------------------------------------------------
# Evidence parsing / version compat (tries v2 -> v1 -> v0, the
# same order as trustee's untagged enum)
# ---------------------------------------------------------------------------


def _parse_evidence_v2(evidence: Dict[str, Any]) -> Evidence:
    version = evidence.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != 2:
        raise ValueError("not a v2 evidence: missing version == 2")
    tpm_quote = evidence["tpm_quote"]
    return Evidence(
        version=2,
        quote_message=bytes.fromhex(tpm_quote["message"]),
        quote_signature=bytes.fromhex(tpm_quote["signature"]),
        quote_pcrs=[bytes.fromhex(p) for p in tpm_quote["pcrs"]],
        hcl_report=_b64_decode_nopad(evidence["hcl_report"]),
        vcek=_load_x509_certificate(_b64_decode_nopad(evidence["vcek"])),
        cc_eventlog=(base64.b64decode(evidence["cc_eventlog"], validate=True) if evidence.get("cc_eventlog") else None),
    )


def _parse_evidence_v1(evidence: Dict[str, Any]) -> Evidence:
    version = evidence.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise ValueError("not a v1 evidence: missing version == 1")
    tpm_quote = evidence["tpm_quote"]
    return Evidence(
        version=1,
        quote_message=bytes.fromhex(tpm_quote["message"]),
        quote_signature=bytes.fromhex(tpm_quote["signature"]),
        quote_pcrs=[bytes.fromhex(p) for p in tpm_quote["pcrs"]],
        hcl_report=_b64_decode_nopad(evidence["hcl_report"]),
        vcek=_load_x509_certificate(_b64_decode_nopad(evidence["vcek"])),
    )


def _parse_evidence_v0(evidence: Dict[str, Any]) -> Evidence:
    # like trustee's serde deserialization of the untagged enum, unknown
    # fields (e.g. a stray "version") are ignored by the v0 shape
    quote = evidence["quote"]
    vcek = evidence["vcek"]
    if isinstance(vcek, bytes):
        # not producible from JSON; supports direct programmatic callers
        # of verify_attestation() passing an already-parsed dict
        vcek = vcek.decode("utf-8")
    if not isinstance(vcek, str):
        raise ValueError("v0 vcek must be a PEM string")
    return Evidence(
        version=0,
        quote_message=_decode_byte_array(quote["message"]),
        quote_signature=_decode_byte_array(quote["signature"]),
        quote_pcrs=[_decode_byte_array(p) for p in quote["pcrs"]],
        hcl_report=_decode_byte_array(evidence["report"]),
        vcek=_load_x509_certificate(vcek.encode("utf-8"), pem=True),
    )


def parse_evidence(evidence: Dict[str, Any]) -> Evidence:
    """Normalize v0/v1/v2 evidence into the internal representation.

    Version detection tries the latest version first and falls back to
    older ones, mirroring trustee's untagged enum Evidence { V2, V1, V0 }.
    """
    if not isinstance(evidence, dict):
        raise ValueError(f"evidence must be a JSON object, got {type(evidence).__name__}")
    attempts = []
    for version, parser in ((2, _parse_evidence_v2), (1, _parse_evidence_v1), (0, _parse_evidence_v0)):
        try:
            parsed = parser(evidence)
            logger.debug("Evidence parsed as version %d", parsed.version)
            return parsed
        except (AttributeError, KeyError, TypeError, ValueError) as e:
            attempts.append(f"v{version}: {e}")
            logger.debug("Evidence does not parse as v%d: %s", version, e)
    raise ValueError(f"evidence matches no known version ({'; '.join(attempts)})")


# ---------------------------------------------------------------------------
# HCL report parsing (nested SNP report)
# ---------------------------------------------------------------------------


def _jwk_to_rsa_public_key(jwk: Dict[str, Any]) -> rsa.RSAPublicKey:
    if jwk.get("kty") != "RSA":
        raise ValueError(f"unsupported JWK kty {jwk.get('kty')}")
    n_b64 = jwk.get("n")
    e_b64 = jwk.get("e")
    if not isinstance(n_b64, str) or not isinstance(e_b64, str):
        raise ValueError("invalid RSA JWK: 'n' and 'e' must be base64 strings")
    n = int.from_bytes(_b64_decode_nopad(n_b64), "big")
    e = int.from_bytes(_b64_decode_nopad(e_b64), "big")
    try:
        return rsa.RSAPublicNumbers(e, n).public_key()
    except ValueError as err:
        raise ValueError(f"invalid RSA JWK: {err}") from err


def _parse_hcl_header(hcl_report: bytes) -> HclReportHeader:
    """Validate the HCL container header; returns the parsed header fields."""
    if len(hcl_report) < HCL_RUNTIME_DATA_OFFSET:
        raise ValueError(f"HCL report too short: {len(hcl_report)} bytes, expected at least {HCL_RUNTIME_DATA_OFFSET}")

    magic, version, report_size, request_type, status, _reserved = struct.unpack_from("<6I", hcl_report, 0)
    logger.debug(
        "HCL header: magic=0x%08x version=%d report_size=%d request_type=%d status=%d",
        magic,
        version,
        report_size,
        request_type,
        status,
    )
    if magic != HCL_HEADER_MAGIC:
        raise ValueError(f"invalid HCL magic 0x{magic:08x}")
    if version not in (1, 2):
        raise ValueError(f"unsupported HCL container version {version}")
    if request_type != HCL_HEADER_REQUEST_TYPE_SEV_SNP:
        raise ValueError(f"unsupported HCL request type {request_type}")
    return HclReportHeader(version=version, report_size=report_size, request_type=request_type, status=status)


def _parse_hcl_runtime_data(hcl_report: bytes) -> HclRuntimeData:
    """Slice out and validate the runtime data area; returns the parsed fields with the claims bytes."""
    runtime = hcl_report[HCL_RUNTIME_DATA_OFFSET:]
    if len(runtime) < HCL_RUNTIME_DATA_HEADER_SIZE:
        raise ValueError(
            f"HCL report runtime data truncated: {len(runtime)} bytes, "
            f"expected at least {HCL_RUNTIME_DATA_HEADER_SIZE}"
        )
    data_size, rt_version, rt_report_type, hash_type, claim_size = struct.unpack_from("<5I", runtime, 0)
    logger.debug(
        "HCL runtime data: data_size=%d version=%d report_type=%d hash_type=%d claim_size=%d",
        data_size,
        rt_version,
        rt_report_type,
        hash_type,
        claim_size,
    )
    if rt_version != HCL_RUNTIME_DATA_VERSION:
        raise ValueError(f"unsupported runtime data version {rt_version}")
    if rt_report_type != HCL_RUNTIME_DATA_REPORT_TYPE_SEV_SNP:
        raise ValueError(f"unsupported runtime data report type {rt_report_type}")
    if hash_type not in _RUNTIME_DATA_HASHES:
        raise ValueError(
            f"unsupported runtime data hash type {hash_type} "
            f"(supported: {', '.join(str(t) for t in sorted(_RUNTIME_DATA_HASHES))})"
        )
    if data_size != HCL_RUNTIME_DATA_HEADER_SIZE + claim_size:
        raise ValueError(
            f"runtime data header mismatch: data_size is {data_size} but header "
            f"{HCL_RUNTIME_DATA_HEADER_SIZE} + claim_size {claim_size} was expected"
        )
    if len(runtime) < data_size:
        raise ValueError(f"runtime data truncated: {len(runtime)} bytes available, data_size says {data_size}")

    claims_bytes = runtime[HCL_RUNTIME_DATA_HEADER_SIZE : HCL_RUNTIME_DATA_HEADER_SIZE + claim_size]
    return HclRuntimeData(
        data_size=data_size,
        version=rt_version,
        report_type=rt_report_type,
        hash_type=hash_type,
        claim_size=claim_size,
        claims_bytes=claims_bytes,
    )


def _extract_ak_pub(claims: Dict[str, Any]) -> rsa.RSAPublicKey:
    """Find the HCLAkPub JWK in the runtime claims and convert it to an RSA key."""
    keys = claims.get("keys")
    if not isinstance(keys, list):
        raise ValueError("runtime claims 'keys' must be a list")
    ak_jwk = None
    for key in keys:
        if isinstance(key, dict) and key.get("kid") == "HCLAkPub":
            ak_jwk = key
            break
    if ak_jwk is None:
        raise ValueError("runtime claims do not contain HCLAkPub")
    return _jwk_to_rsa_public_key(ak_jwk)


def _extract_user_data(claims: Dict[str, Any]) -> Optional[bytes]:
    """Decode the optional 'user-data' hex string from the runtime claims."""
    if "user-data" not in claims:
        return None
    user_data_str = claims["user-data"]
    if not isinstance(user_data_str, str):
        raise ValueError("runtime claims 'user-data' must be a hex string")
    try:
        return bytes.fromhex(user_data_str)
    except ValueError as e:
        raise ValueError(f"invalid user-data hex: {e}") from e


def parse_hcl_report(hcl_report: bytes) -> HclReport:
    """Parse the Azure HCL container: header + SNP report + runtime claims."""
    header = _parse_hcl_header(hcl_report)

    snp_report = hcl_report[SNP_REPORT_OFFSET : SNP_REPORT_OFFSET + SNP_REPORT_SIZE]
    if len(snp_report) != SNP_REPORT_SIZE:
        raise ValueError("HCL report does not contain a full SNP report payload")

    runtime = _parse_hcl_runtime_data(hcl_report)
    try:
        claims = json.loads(runtime.claims_bytes)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid runtime claims JSON: {e}") from e
    except RecursionError as e:
        # deeply nested JSON (serde_json caps depth at 128; do not crash)
        raise ValueError("runtime claims JSON is nested too deeply") from e
    if not isinstance(claims, dict):
        raise ValueError("runtime claims must be a JSON object")

    logger.debug("HCL runtime claims: %s", claims)

    ak_pub = _extract_ak_pub(claims)
    user_data = _extract_user_data(claims)

    hcl = HclReport(
        raw=hcl_report,
        snp_report=snp_report,
        claims_bytes=runtime.claims_bytes,
        hash_type=runtime.hash_type,
        claims=claims,
        ak_pub=ak_pub,
        user_data=user_data,
    )
    logger.debug(
        "Parsed HCL report: %d bytes, container v%d, SNP report %d bytes, claims %d bytes, "
        "hash type %d, user-data=%s, AK %d-bit RSA",
        len(hcl_report),
        header.version,
        len(snp_report),
        runtime.claim_size,
        runtime.hash_type,
        user_data.hex() if user_data is not None else "(absent)",
        ak_pub.key_size,
    )
    return hcl


def _report_generation(snp_report: bytes) -> str:
    """Derive the processor generation from the report's CPUID (v3+).

    Family 0x19 covers Milan (models < 0x10) and Genoa (models >= 0x10);
    family 0x1A is Turin. Reports without CPUID (version 2, where the
    region is reserved) are rejected: the generation cannot be established
    from the report, and guessing would misroute the VCEK chain pinning.
    """
    family = snp_report[SNP_REPORT_CPUID_FAMILY_OFFSET]
    model = snp_report[SNP_REPORT_CPUID_MODEL_OFFSET]
    if family == SNP_CPUID_FAMILY_TURIN:
        return "turin"
    if family == SNP_CPUID_FAMILY_MILAN_GENOA:
        return "genoa" if model >= SNP_CPUID_GENOA_MIN_MODEL else "milan"
    if family == 0:
        raise ValueError(
            "SNP report is missing the CPUID family/model fields (version 2 "
            "reports carry none); the processor generation cannot be "
            "determined, refusing to guess"
        )
    raise ValueError(f"unknown SNP report CPUID family {family}")


def _decode_tcb(reported_tcb: bytes, generation: str) -> Tuple[Optional[int], int, int, int, int]:
    """Decode the reported TCB per generation.

    Returns (fmc, bootloader, tee, snp, microcode). The byte layout is
    generation-dependent (AMD SEV-SNP FW ABI #56860 section 2.2; virtee/sev
    from_legacy_bytes / from_turin_bytes):

    - Milan/Genoa: [bootloader, tee, reserved x4, snp, microcode]
    - Turin:       [fmc, bootloader, tee, snp, reserved x3, microcode]
    """
    if generation == "turin":
        return reported_tcb[0], reported_tcb[1], reported_tcb[2], reported_tcb[3], reported_tcb[7]
    return None, reported_tcb[0], reported_tcb[1], reported_tcb[6], reported_tcb[7]


def _check_key_info(snp_report: bytes) -> None:
    """Reject reports that were not signed by the VCEK.

    The field is only used to reject, never to route: the binding to a
    VCEK is enforced cryptographically by the chain, chip-id and signature
    checks (phases 6-8).
    """
    key_info = struct.unpack_from("<I", snp_report, SNP_REPORT_KEY_INFO_OFFSET)[0]
    signing_key = (key_info >> 2) & 0x7
    if signing_key == SNP_SIGNING_KEY_VLEK:
        raise ValueError("SNP report was signed with VLEK; only VCEK-signed reports are supported")
    if signing_key != SNP_SIGNING_KEY_VCEK:
        raise ValueError(f"SNP report signing key type {signing_key} is not supported (only VCEK)")
    if (key_info >> 1) & 1:
        raise ValueError("SNP report is not signed (MASK_CHIP_KEY is set)")


def parse_snp_report(snp_report: bytes) -> SnpReport:
    """Extract the verifier-relevant fields of the AMD SNP report."""
    if len(snp_report) != SNP_REPORT_SIZE:
        raise ValueError(f"SNP report must be exactly {SNP_REPORT_SIZE} bytes, got {len(snp_report)}")
    _check_key_info(snp_report)
    generation = _report_generation(snp_report)
    tcb_fmc, tcb_bootloader, tcb_tee, tcb_snp, tcb_microcode = _decode_tcb(
        snp_report[SNP_REPORT_REPORTED_TCB_OFFSET : SNP_REPORT_REPORTED_TCB_OFFSET + 8], generation
    )
    return SnpReport(
        raw=snp_report,
        policy=struct.unpack_from("<Q", snp_report, SNP_REPORT_POLICY_OFFSET)[0],
        vmpl=struct.unpack_from("<I", snp_report, SNP_REPORT_VMPL_OFFSET)[0],
        platform_info=struct.unpack_from("<Q", snp_report, SNP_REPORT_PLATFORM_INFO_OFFSET)[0],
        report_data=snp_report[SNP_REPORT_REPORT_DATA_OFFSET : SNP_REPORT_REPORT_DATA_OFFSET + 64],
        measurement=snp_report[SNP_REPORT_MEASUREMENT_OFFSET : SNP_REPORT_MEASUREMENT_OFFSET + 48],
        host_data=snp_report[SNP_REPORT_HOST_DATA_OFFSET : SNP_REPORT_HOST_DATA_OFFSET + 32],
        reported_tcb=snp_report[SNP_REPORT_REPORTED_TCB_OFFSET : SNP_REPORT_REPORTED_TCB_OFFSET + 8],
        chip_id=snp_report[SNP_REPORT_CHIP_ID_OFFSET : SNP_REPORT_CHIP_ID_OFFSET + 64],
        generation=generation,
        tcb_fmc=tcb_fmc,
        tcb_bootloader=tcb_bootloader,
        tcb_tee=tcb_tee,
        tcb_snp=tcb_snp,
        tcb_microcode=tcb_microcode,
    )


# ---------------------------------------------------------------------------
# TPMS_ATTEST parsing
# ---------------------------------------------------------------------------


def parse_tpm_attest(message: bytes) -> TpmAttest:
    """Parse a TPMS_ATTEST quote structure (TPM 2.0 Part 2, big-endian).

    Walks magic, type, qualifiedSigner, extraData, clockInfo,
    firmwareVersion, pcrSelect and pcrDigest, requiring the parse to
    consume the message exactly.
    """
    offset = 0

    def take(size: int) -> bytes:
        nonlocal offset
        if offset + size > len(message):
            raise ValueError(f"TPMS_ATTEST truncated at offset {offset} ({len(message)} bytes)")
        chunk = message[offset : offset + size]
        offset += size
        return chunk

    def take_tpm2b() -> bytes:
        (length,) = struct.unpack(">H", take(2))
        return take(length)

    (magic,) = struct.unpack(">I", take(4))
    if magic != TPM_GENERATED:
        raise ValueError(f"invalid TPMS_ATTEST magic 0x{magic:08x}")
    (attest_type,) = struct.unpack(">H", take(2))
    if attest_type != TPM_ST_ATTEST_QUOTE:
        raise ValueError(f"TPM attestation type 0x{attest_type:04x} is not a quote")

    take_tpm2b()  # qualifiedSigner (name of the signing AK)
    extra_data = take_tpm2b()

    take(17)  # clockInfo (clock, resetCount, restartCount, safe)
    take(8)  # firmwareVersion

    (count,) = struct.unpack(">I", take(4))
    hash_algs = []
    bitmap = b""
    for _ in range(count):
        (hash_alg,) = struct.unpack(">H", take(2))
        (sizeof_select,) = struct.unpack(">B", take(1))
        hash_algs.append(hash_alg)
        bitmap += take(sizeof_select)
    pcr_digest = take_tpm2b()

    if offset != len(message):
        raise ValueError(f"TPMS_ATTEST has {len(message) - offset} trailing bytes")

    logger.debug(
        "TPMS_ATTEST: extraData=%s pcrSelect=%d bank(s) bitmap=%s pcrDigest=%s",
        extra_data.hex(),
        count,
        bitmap.hex(),
        pcr_digest.hex(),
    )
    return TpmAttest(
        extra_data=extra_data,
        pcr_digest=pcr_digest,
        pcr_select_hash_algs=hash_algs,
        pcr_select_bitmap=bitmap,
    )


# ---------------------------------------------------------------------------
# Trust anchors
# ---------------------------------------------------------------------------


def _name_common_name(name: x509.Name) -> str:
    """The first common-name attribute of an X.509 name, or the empty string."""
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return ""
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


def _cert_common_name(cert: x509.Certificate) -> str:
    """The subject common name of a certificate."""
    return _name_common_name(cert.subject)


def _generation_from_name(name: x509.Name) -> Optional[str]:
    """The processor generation named in an X.509 name's common name, if any."""
    cn = _name_common_name(name).lower()
    for generation in PROCESSOR_GENERATIONS:
        if generation in cn:
            return generation
    return None


def _classify_anchor_bundle(certs: List[x509.Certificate]) -> Tuple[x509.Certificate, x509.Certificate]:
    """Identify the ASK and ARK in an AMD KDS-style certificate bundle.

    The ARK is the self-signed certificate; certificates for the VLEK
    path (VLEK and ASVK, not used for VCEK validation) are skipped; the
    remaining certificate is the ASK. A second ASK candidate is an error
    rather than a silent overwrite.
    """
    ask = ark = None
    for cert in certs:
        if cert.subject == cert.issuer:  # the self-signed root
            if ark is not None:
                raise ValueError("multiple self-signed certificates in the bundle (ambiguous ARK)")
            ark = cert
        else:
            cn = _cert_common_name(cert).lower()
            if "vlek" in cn or "asvk" in cn:
                continue
            if ask is not None:
                raise ValueError("multiple candidate ASK certificates in the bundle")
            ask = cert
    if ask is None or ark is None:
        raise ValueError("could not identify an ASK/ARK pair in the certificate bundle")
    return ask, ark


def _check_anchor_generation(ask: x509.Certificate, ark: x509.Certificate, expected: Optional[str] = None) -> str:
    """The ASK and ARK must name the same processor generation (and, when
    fetching for a specific generation, the one requested)."""
    gen_ask = _generation_from_name(ask.subject)
    gen_ark = _generation_from_name(ark.subject)
    if gen_ask is None or gen_ark is None or gen_ask != gen_ark:
        raise ValueError(f"ASK/ARK generation mismatch in anchor bundle (ASK: {gen_ask}, ARK: {gen_ark})")
    if expected is not None and gen_ask != expected:
        raise ValueError(f"anchor chain names {gen_ask}, expected {expected}")
    return gen_ask


def _validate_anchor_pair(ask: x509.Certificate, ark: x509.Certificate) -> bool:
    """Validate an ASK/ARK pair: the ARK is self-signed and signs the ASK,
    and the ASK itself is not self-signed."""
    if ask.subject == ask.issuer:
        return False
    if not _rsa_pss_verify(ark.public_key(), ark.signature, ark.tbs_certificate_bytes):
        return False
    return _rsa_pss_verify(ark.public_key(), ask.signature, ask.tbs_certificate_bytes)


def load_trust_anchors(path: str) -> Dict[str, Tuple[x509.Certificate, x509.Certificate]]:
    """Load per-generation ASK/ARK anchor pairs from a trust store directory.

    ``path`` must be a directory of PEM files. Each PEM may be an AMD
    KDS-style bundle (ASK, ARK, VLEK in any order); the ARK is identified
    as the self-signed certificate, the VLEK is ignored. Returns a mapping
    generation -> (ask, ark).
    """
    if not os.path.isdir(path):
        logger.warning("Trust anchor store is not a directory: %s", path)
        raise ValueError(f"trust anchor store is not a directory: {path}")
    files = [os.path.join(path, f) for f in sorted(os.listdir(path)) if f.endswith(".pem")]

    chains: Dict[str, Tuple[x509.Certificate, x509.Certificate]] = {}
    for pem_file in files:
        with open(pem_file, "rb") as f:
            try:
                certs = _load_x509_bundle(f.read())
            except ValueError as e:
                # an unparseable file is skipped, like a non-anchor file
                logger.warning("Skipping %s: could not load certificates (%s)", pem_file, e)
                continue
        try:
            ask, ark = _classify_anchor_bundle(certs)
        except ValueError as e:
            # not an ASK/ARK bundle (e.g. a VCEK certificate) - skip it
            logger.debug("Skipping %s: %s", pem_file, e)
            continue
        if not _validate_anchor_pair(ask, ark):
            logger.warning("Skipping %s: ASK/ARK pair failed validation", pem_file)
            continue
        try:
            generation = _check_anchor_generation(ask, ark)
        except ValueError as e:
            logger.warning("Skipping %s: %s", pem_file, e)
            continue
        if generation in chains:
            # two files claiming the same generation must be an explicit
            # error, not a silent overwrite of the root of trust
            logger.warning("Duplicate trust anchor for generation %s: %s", generation, pem_file)
            raise ValueError(f"duplicate trust anchor for generation {generation}: {pem_file}")
        chains[generation] = (ask, ark)
    if not chains:
        logger.warning("No usable trust anchors found in %s", path)
        raise ValueError(f"no trust anchors found in {path}")
    return chains


def fetch_kds_chain(generation: str, timeout: float = KDS_FETCH_TIMEOUT) -> Tuple[x509.Certificate, x509.Certificate]:
    """Fetch and validate the ASK/ARK chain for a generation from the AMD KDS.

    Provisioning utility only: used to fill or refresh a local trust store
    (see amd_cert_store/README.md); the verification path never calls this.
    The fetched bundle is validated before it is returned: the ARK must be
    self-signed and the ASK signed by the ARK (RSA-PSS SHA-384). This is
    internal consistency, not authenticity -- fetch from a trusted network
    and review the recorded sha256 of the result.
    """
    url = KDS_CERT_CHAIN_URL.format(generation=generation.capitalize())
    response = requests.get(url, timeout=timeout, allow_redirects=False)
    if response.status_code != 200:
        raise ValueError(f"KDS returned status {response.status_code} for {url}")
    try:
        certs = _load_x509_bundle(response.content)
    except ValueError as e:
        raise ValueError(f"KDS response for {generation} is not a valid PEM certificate bundle: {e}") from e
    ask, ark = _classify_anchor_bundle(certs)
    if not _validate_anchor_pair(ask, ark):
        raise ValueError(f"KDS chain for {generation} failed validation (ARK self-signature or ASK signature)")
    _check_anchor_generation(ask, ark, expected=generation)
    return ask, ark


def resolve_trust_anchors(path: Optional[str] = None) -> Dict[str, Tuple[x509.Certificate, x509.Certificate]]:
    """Return the per-generation ASK/ARK chains from the local trust store.

    Resolution order: an explicit store ``path`` (a directory), then the
    ``[verifier] amd_anchor_path`` configuration option (empty or unset
    means the default), then the certificates bundled with the package.
    Nothing is fetched from the network; use fetch_kds_chain() to
    provision or refresh a store. A generation missing from the store is
    simply unavailable and evidence of that generation fails closed.
    Chains are cached in memory for the process lifetime (an explicit
    ``path`` re-resolves and replaces the cache).
    """
    if path is None:
        if _ANCHOR_CACHE:
            # return a snapshot so callers cannot mutate the process-global cache
            return dict(_ANCHOR_CACHE)
        path = config.get("verifier", "amd_anchor_path", fallback=BUNDLED_ANCHOR_STORE) or BUNDLED_ANCHOR_STORE
    chains = load_trust_anchors(path)
    _ANCHOR_CACHE.clear()
    _ANCHOR_CACHE.update(chains)
    # the active root of trust must be visible in the log: which
    # generations, from which store (bundled or configured)
    logger.info("Loaded AMD ASK/ARK trust anchors for %s from %s", ", ".join(sorted(chains)), path)
    return dict(chains)


def clear_anchor_cache() -> None:
    """Empty the in-memory ASK/ARK anchor cache (intended for tests)."""
    _ANCHOR_CACHE.clear()


# ---------------------------------------------------------------------------
# Verification phases (each adds a failure event and returns False on error)
# ---------------------------------------------------------------------------


def _pss_padding() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.DIGEST_LENGTH)


def _rsa_pss_verify(public_key: Any, signature: bytes, data: bytes) -> bool:
    """RSA-PSS(SHA-384) verification; the AMD chain certificates are RSA."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        logger.debug("Certificate public key is not RSA, cannot verify with RSA-PSS")
        return False
    try:
        public_key.verify(signature, data, _pss_padding(), hashes.SHA384())
        return True
    except InvalidSignature:
        return False


def verify_tpm_signature(
    quote_message: bytes, quote_signature: bytes, ak_pub: rsa.RSAPublicKey, failure: Failure
) -> bool:
    """Check the RSA-SHA256 signature over the TPM quote message with the AK from the HCL claims."""
    try:
        ak_pub.verify(quote_signature, quote_message, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        failure.add_event("quote_signature", {"message": "vTPM quote is not signed by AKpub"}, False)
        return False
    logger.debug("TPM quote signature verified with HCLAkPub")
    return True


def verify_tpm_nonce(attest: TpmAttest, nonce: bytes, failure: Failure) -> bool:
    """Check that the quote extraData matches the expected evidence nonce."""
    if attest.extra_data != nonce:
        failure.add_event(
            "quote_nonce",
            {"message": "TPM quote nonce doesn't match expected report_data"},
            False,
        )
        return False
    logger.debug("TPM quote nonce matches expected report_data")
    return True


def verify_tpm_pcrs(pcrs: List[bytes], attest: TpmAttest, failure: Failure) -> bool:
    """Check that SHA256 over the PCR list matches the quoted pcrDigest."""
    if len(pcrs) != EXPECTED_PCR_COUNT or any(len(pcr) != PCR_SIZE for pcr in pcrs):
        failure.add_event(
            "pcr_digest",
            {"message": f"expected {EXPECTED_PCR_COUNT} PCRs of {PCR_SIZE} bytes"},
            False,
        )
        return False
    if attest.pcr_select_hash_algs != [TPM_ALG_SHA256]:
        failure.add_event(
            "pcr_digest",
            {"message": f"unexpected pcrSelect banks {attest.pcr_select_hash_algs}"},
            False,
        )
        return False

    actual = hashlib.sha256(b"".join(pcrs)).digest()
    if not hmac.compare_digest(actual, attest.pcr_digest):
        failure.add_event(
            "pcr_digest",
            {"message": "Digest of PCRs does not match digest in Quote"},
            False,
        )
        return False
    logger.debug("PCR digest matches the digest in the quote")
    return True


def verify_report_data(hcl: HclReport, snp: SnpReport, failure: Failure) -> bool:
    """Check that the hash of the runtime claims (per the runtime data hash type) equals the matching report_data prefix."""
    # the claims hash is committed into report_data over the type-appropriate
    # prefix; the hash type comes from the runtime data header (the format
    # defines SHA-256/384/512; all three are accepted)
    claims_hash = _RUNTIME_DATA_HASHES[hcl.hash_type](hcl.claims_bytes).digest()
    if not hmac.compare_digest(claims_hash, snp.report_data[: len(claims_hash)]):
        failure.add_event(
            "hcl_binding",
            {"message": "HCL variable data digest doesn't match SNP report data"},
            False,
        )
        return False
    logger.debug("HCL runtime claims are bound to the SNP report_data")
    return True


def verify_user_data(hcl: HclReport, nonce: bytes, failure: Failure, evidence_version: int) -> bool:
    """Check that the HCL user-data carries the expected nonce (v2+ only).

    The user-data is the nonce zero-padded to 64 bytes by the producer, so
    only the prefix of the expected nonce length is compared. On v0/v1
    evidence the HCL report is generated once at boot and its user-data is
    stale, so the check is skipped.
    """
    if evidence_version < 2:
        logger.debug("Skipping user-data check (evidence v%d: boot-time report, stale user-data)", evidence_version)
        return True
    if hcl.user_data is None or hcl.user_data[: len(nonce)] != nonce:
        failure.add_event(
            "user_data",
            {"message": "User-data in HCL variable data doesn't match report_data"},
            False,
        )
        return False
    logger.debug("HCL user-data matches the expected report_data")
    return True


def verify_vcek_chain(
    vcek: x509.Certificate,
    snp: SnpReport,
    chains: Dict[str, Tuple[x509.Certificate, x509.Certificate]],
    failure: Failure,
) -> bool:
    """Validate the ARK -> ASK -> VCEK chain and the VCEK validity period.

    The chain is pinned to the report's processor generation: genuine
    evidence always carries a VCEK of the same generation as the report,
    so trying other generations' chains would only accept mixed-chip
    evidence.
    """
    generation = snp.generation
    chain = chains.get(generation)
    if chain is None:
        failure.add_event(
            "vcek_chain",
            {"message": f"the {generation} ASK/ARK chain is not in the trust store"},
            False,
        )
        return False

    try:
        issuer_gen = _generation_from_name(vcek.issuer)
    except ValueError:
        # an undecodable issuer name: no warning, the pinned chain walk decides
        issuer_gen = None
    if issuer_gen is not None and issuer_gen != generation:
        logger.warning("VCEK issuer suggests %s but the report is %s; using the report's chain", issuer_gen, generation)

    ask, ark = chain
    # ARK self-signed, ASK signed by the ARK, VCEK signed by the ASK
    if not _rsa_pss_verify(ark.public_key(), ark.signature, ark.tbs_certificate_bytes):
        failure.add_event(
            "vcek_chain",
            {"message": f"ARK of the {generation} chain is not self-signed"},
            False,
        )
        return False
    if not _rsa_pss_verify(ark.public_key(), ask.signature, ask.tbs_certificate_bytes):
        failure.add_event(
            "vcek_chain",
            {"message": f"ASK of the {generation} chain is not signed by the ARK"},
            False,
        )
        return False
    if not _rsa_pss_verify(ask.public_key(), vcek.signature, vcek.tbs_certificate_bytes):
        failure.add_event(
            "vcek_chain",
            {"message": "Failed to validate VCEK against the AMD certificate chains"},
            False,
        )
        return False

    if not _cert_within_validity(vcek):
        failure.add_event(
            "vcek_validity",
            {"message": "VCEK certificate is outside its validity period"},
            False,
        )
        return False

    logger.debug("VCEK validated against the %s certificate chain", generation)
    return True


def _cert_within_validity(cert: x509.Certificate) -> bool:
    # the timezone-aware properties require cryptography >= 42 (see
    # requirements.txt)
    now = datetime.now(timezone.utc)
    return cert.not_valid_before_utc <= now < cert.not_valid_after_utc


def _get_oid_value(cert: x509.Certificate, oid: str) -> Optional[bytes]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value
    except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError):
        # a missing, malformed or duplicated extension block is treated as
        # a missing extension, so the caller fails closed (extension
        # parsing is lazy, so a duplicated OID survives certificate loading
        # and would raise here; DuplicateExtension is not a ValueError)
        return None
    if not isinstance(ext, x509.UnrecognizedExtension):
        return None
    return bytes(ext.value)


def _decode_oid_int(raw: bytes) -> int:
    """Decode an AMD SPL extension value (a DER INTEGER, in practice 02 01 XX)."""
    if len(raw) < 2 or raw[0] != 0x02:
        raise ValueError(f"invalid DER INTEGER extension value {raw.hex()}")
    (length,) = raw[1:2]
    if len(raw) < 2 + length:
        raise ValueError(f"truncated DER INTEGER extension value {raw.hex()}")
    return int.from_bytes(raw[2 : 2 + length], "big")


def _decode_oid_octets(raw: bytes, size: int) -> bytes:
    """Decode an AMD HW_ID extension value: raw bytes or DER OCTET STRING."""
    if len(raw) == size:
        return raw
    if len(raw) == size + 2 and raw[0] == 0x04 and raw[1] == size:
        return raw[2:]
    raise ValueError(f"invalid extension value of {len(raw)} bytes, expected {size}")


def verify_vcek_oids(vcek: x509.Certificate, snp: SnpReport, failure: Failure) -> bool:
    """Check that the VCEK AMD OID extensions match the report (chip id + TCB)."""
    hw_id = _get_oid_value(vcek, HW_ID_OID)
    if hw_id is None:
        failure.add_event("vcek_chip_id", {"message": "VCEK certificate has no usable HW_ID extension"}, False)
        return False
    try:
        if _decode_oid_octets(hw_id, len(snp.chip_id)) != snp.chip_id:
            failure.add_event("vcek_chip_id", {"message": "Chip ID mismatch"}, False)
            return False
    except ValueError as e:
        failure.add_event("vcek_chip_id", {"message": str(e)}, False)
        return False

    # the TCB byte layout and the OID<->byte mapping are generation-dependent
    # (Turin adds the FMC component and shifts the others; see _decode_tcb)
    tcb_values: List[Tuple[str, Optional[int], str]]
    if snp.generation == "turin":
        tcb_values = [
            (UCODE_SPL_OID, snp.tcb_microcode, "microcode"),
            (SNP_SPL_OID, snp.tcb_snp, "snp"),
            (TEE_SPL_OID, snp.tcb_tee, "tee"),
            (LOADER_SPL_OID, snp.tcb_bootloader, "bootloader"),
            (FMC_SPL_OID, snp.tcb_fmc, "fmc"),
        ]
    else:
        tcb_values = [
            (UCODE_SPL_OID, snp.tcb_microcode, "microcode"),
            (SNP_SPL_OID, snp.tcb_snp, "snp"),
            (TEE_SPL_OID, snp.tcb_tee, "tee"),
            (LOADER_SPL_OID, snp.tcb_bootloader, "bootloader"),
        ]
    for oid, expected, name in tcb_values:
        raw = _get_oid_value(vcek, oid)
        if raw is None:
            failure.add_event(
                "vcek_oid_mismatch", {"message": f"VCEK certificate has no usable {name} SPL extension"}, False
            )
            return False
        try:
            actual = _decode_oid_int(raw)
        except ValueError as e:
            failure.add_event("vcek_oid_mismatch", {"message": str(e)}, False)
            return False
        if actual != expected:
            failure.add_event(
                "vcek_oid_mismatch",
                {"message": f"{name.capitalize()} version mismatch"},
                False,
            )
            return False
        logger.debug("VCEK %s SPL (%d) matches the report", name, actual)

    return True


def verify_snp_report_signature(vcek: x509.Certificate, snp: SnpReport, failure: Failure) -> bool:
    """Check the VCEK ECDSA-P384/SHA-384 signature over the SNP report."""
    # the R and S scalars each live in a 72-byte little-endian field (AMD ABI
    # spec #56860, Table 141); the remaining signature area is reserved
    sig = snp.raw[SNP_REPORT_SIGNATURE_OFFSET : SNP_REPORT_SIGNATURE_OFFSET + 2 * SNP_REPORT_SIGNATURE_R_SIZE]
    r = int.from_bytes(sig[:SNP_REPORT_SIGNATURE_R_SIZE], "little")
    s = int.from_bytes(sig[SNP_REPORT_SIGNATURE_R_SIZE:], "little")
    try:
        public_key = vcek.public_key()
    except (ValueError, UnsupportedAlgorithm) as e:
        failure.add_event(
            "report_signature",
            {"message": f"VCEK public key cannot be decoded: {e}"},
            False,
        )
        return False
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        failure.add_event(
            "report_signature",
            {"message": "VCEK public key is not an EC key"},
            False,
        )
        return False
    try:
        public_key.verify(
            encode_dss_signature(r, s),
            snp.raw[:SNP_REPORT_SIGNATURE_OFFSET],
            ec.ECDSA(hashes.SHA384()),
        )
    except InvalidSignature:
        failure.add_event(
            "report_signature",
            {"message": "VCEK public key does not sign the SEV-SNP attestation report"},
            False,
        )
        return False
    logger.debug("SNP report signature verified with the VCEK public key")
    return True


def verify_vmpl(snp: SnpReport, failure: Failure) -> bool:
    """Check that the SNP report was issued at VMPL 0 (the HCL)."""
    if snp.vmpl != SNP_REPORT_REQUIRED_VMPL:
        failure.add_event(
            "vmpl",
            {"message": f"VMPL of SNP report is not {SNP_REPORT_REQUIRED_VMPL} (it is {snp.vmpl})"},
            False,
        )
        return False
    logger.debug("SNP report VMPL is %d", snp.vmpl)
    return True


def verify_init_data(init_data_hash: Optional[bytes], pcrs: List[bytes], failure: Failure) -> bool:
    """Optionally check that PCR[8] binds sha256(0x00*32 || init_data_hash)."""
    if init_data_hash is None:
        logger.debug("No expected init_data hash, skipping init_data verification")
        return True

    # unreachable through verify_attestation (phase 3 checked the PCR list
    # shape); guards direct callers against a short list
    if len(pcrs) <= INIT_DATA_PCR:
        failure.add_event(
            "init_data",
            {"message": f"not enough PCRs to check init-data binding (need PCR{INIT_DATA_PCR})"},
            False,
        )
        return False

    digest = hashlib.sha256(b"\x00" * 32 + init_data_hash).digest()
    if not hmac.compare_digest(pcrs[INIT_DATA_PCR], digest):
        failure.add_event(
            "init_data",
            {"message": (f"Expected init_data digest is different from the content of PCR{INIT_DATA_PCR}")},
            False,
        )
        return False
    logger.debug("PCR%d matches the expected init_data digest", INIT_DATA_PCR)
    return True


# ---------------------------------------------------------------------------
# Claims assembly
# ---------------------------------------------------------------------------


def parse_claims(snp: SnpReport, attest: TpmAttest, pcrs: List[bytes]) -> Dict[str, Any]:
    """Build the parsed-claims map consumed by the policy layer
    (report_data, init_data, tpm PCR keys)."""
    # unreachable through verify_attestation (phase 3 checked the PCR list
    # shape); guards direct callers against a short list
    if len(pcrs) <= INIT_DATA_PCR:
        raise ValueError(f"not enough PCRs to assemble claims (need PCR{INIT_DATA_PCR})")

    policy = snp.policy
    claims: Dict[str, Any] = {
        # policy fields (the policy is a little-endian u64: ABI minor is the
        # low byte, ABI major the next one)
        "policy_abi_major": str((policy >> 8) & 0xFF),
        "policy_abi_minor": str(policy & 0xFF),
        "policy_smt_allowed": str(bool(policy & (1 << 16))).lower(),
        "policy_migrate_ma": str(bool(policy & (1 << 18))).lower(),
        "policy_debug_allowed": str(bool(policy & (1 << 19))).lower(),
        "policy_single_socket": str(bool(policy & (1 << 20))).lower(),
        # versioning info
        "reported_tcb_bootloader": str(snp.tcb_bootloader),
        "reported_tcb_tee": str(snp.tcb_tee),
        "reported_tcb_snp": str(snp.tcb_snp),
        "reported_tcb_microcode": str(snp.tcb_microcode),
        # platform info (bit 0 = SMT, bit 1 = TSME)
        "platform_tsme_enabled": str(bool(snp.platform_info & (1 << 1))).lower(),
        "platform_smt_enabled": str(bool(snp.platform_info & (1 << 0))).lower(),
        # measurements
        "measurement": base64.b64encode(snp.measurement).decode("ascii"),
        # extend_claim overwrites report_data with the hex of the quote nonce
        "report_data": attest.extra_data.hex(),
        # extend_claim overwrites init_data with the hex of PCR[8]
        "init_data": pcrs[INIT_DATA_PCR].hex(),
        "tpm": {f"pcr{index:02d}": pcr.hex() for index, pcr in enumerate(pcrs)},
    }
    return claims


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _parse_evidence_parts(
    evidence: Dict[str, Any], init_data_hash: Optional[bytes], failure: Failure
) -> Optional[Tuple[Evidence, HclReport, SnpReport, TpmAttest]]:
    """Decode and parse everything: the evidence JSON, the HCL container
    with the nested SNP report, and the TPMS_ATTEST quote message.

    Returns (evidence, hcl, snp, attest), or None once the failure object
    carries the reason. The TPMS_ATTEST is parsed here, before the phase-1
    crypto, so malformed input fails cheap.
    """
    if init_data_hash is not None and not isinstance(init_data_hash, bytes):
        failure.add_event("invalid_input", {"message": "init_data_hash must be bytes"}, False)
        return None

    # Phase 0 - parse and normalize the evidence
    try:
        parsed = parse_evidence(evidence)
    except (AttributeError, KeyError, TypeError, ValueError) as e:
        failure.add_event("invalid_input", {"message": f"invalid az-snp-vtpm evidence: {e}"}, False)
        return None

    if parsed.cc_eventlog:
        logger.warning("cc_eventlog present in the az-snp-vtpm evidence but its replay is not implemented; ignoring it")

    # Phase 0 - parse the HCL container and the nested SNP report
    try:
        hcl = parse_hcl_report(parsed.hcl_report)
        snp = parse_snp_report(hcl.snp_report)
    except ValueError as e:
        failure.add_event("hcl_report", {"message": str(e)}, False)
        return None

    try:
        attest = parse_tpm_attest(parsed.quote_message)
    except ValueError as e:
        failure.add_event("tpm_message_parse", {"message": str(e)}, False)
        return None

    return (parsed, hcl, snp, attest)


def verify_attestation(
    evidence: Dict[str, Any],
    nonce: bytes,
    init_data_hash: Optional[bytes] = None,
    anchors: Optional[Dict[str, Tuple[x509.Certificate, x509.Certificate]]] = None,
) -> Tuple[Dict[str, Any], Failure]:
    """Verify az-snp-vtpm attestation evidence.

    :param evidence: the evidence dict from the tee-evidence request
    (v0/v1/v2 shapes are accepted, tried latest-first)
    :param nonce: the expected evidence nonce (report_data), i.e. the
    SHA-384 RCAR runtime-data digest the evidence was generated with --
    NOT the raw KBS challenge
    :param init_data_hash: optional expected init-data digest (checked
    against PCR[8])
    :param anchors: optional caller-supplied trust anchors, mapping
    generation -> (ask, ark); when given they replace the local trust
    store entirely (the caller brings its own root of trust, e.g. a
    future policy layer). When absent, anchors are resolved from the
    store: the [verifier] amd_anchor_path option, or the per-generation
    certificates bundled with the package. No network access happens.

    :returns: (claims, failure) -- claims is empty when verification fails
    """
    failure = Failure(Component.TEE)

    # Phase 0 - parse everything: normalize the evidence JSON (v2/v1/v0,
    # latest first), the HCL container, the nested SNP report and the
    # TPMS_ATTEST quote message. Nothing is verified yet; malformed input
    # fails here with a clear event instead of a crash.
    parts = _parse_evidence_parts(evidence, init_data_hash, failure)
    if parts is None:
        return ({}, failure)
    parsed, hcl, snp, attest = parts

    # Phase 1 - quote signature: the RSA signature over the quote message,
    # checked with the AK public key taken from the HCL claims. Proves the
    # quote was signed by the key the report will later vouch for -- the
    # key's genuineness is only established retroactively, in phases 4-8.
    if not verify_tpm_signature(parsed.quote_message, parsed.quote_signature, hcl.ak_pub, failure):
        return ({}, failure)

    # Phase 2 - nonce in the quote: the nonce inside the quote must equal
    # the one we sent. Proves the quote is fresh, not a replay.
    if not verify_tpm_nonce(attest, nonce, failure):
        return ({}, failure)

    # Phase 3 - PCR digest: SHA-256 over the shipped PCR values must equal
    # the digest inside the signed quote. Proves the unsigned PCR list was
    # not swapped after the vTPM signed.
    if not verify_tpm_pcrs(parsed.quote_pcrs, attest, failure):
        return ({}, failure)

    # Phase 4 - HCL <-> SNP binding: SHA-256 over the runtime claims must
    # equal report_data[0..32] of the SNP report. Proves the AK, user-data
    # and VM settings are exactly the ones the report committed to.
    if not verify_report_data(hcl, snp, failure):
        return ({}, failure)

    # Phase 5 - user-data freshness (v2+ only): the HCL user-data must carry
    # our nonce. Proves freshness through the hardware chain as well.
    # Skipped for v0/v1: their report is generated once at boot and carries
    # a stale boot-time user-data.
    if not verify_user_data(hcl, nonce, failure, parsed.version):
        return ({}, failure)

    # Phase 6 - VCEK vendor chain (anchors come from the caller via the
    # anchors parameter, or from the local trust store -- the [verifier]
    # amd_anchor_path option or the bundled per-generation certificates;
    # never from the network): ARK self-signed -> ASK signed by ARK ->
    # VCEK signed by ASK, pinned to the report's generation, within its
    # validity window. Proves the VCEK is a genuine AMD certificate for
    # this CPU generation.
    try:
        chains = anchors if anchors is not None else resolve_trust_anchors()
    except ValueError as e:
        failure.add_event("missing_trust_anchors", {"message": str(e)}, False)
        return ({}, failure)
    if not verify_vcek_chain(parsed.vcek, snp, chains, failure):
        return ({}, failure)

    # Phase 7 - VCEK OID extensions vs the report: the certificate's chip id
    # and TCB levels must match the report. Phase 6 proved the certificate
    # is genuine, but a genuine card for a *different* machine would pass it
    # too. Proves same chip, same firmware: a report from machine A with the
    # certificate of machine B dies here.
    if not verify_vcek_oids(parsed.vcek, snp, failure):
        return ({}, failure)

    # Phase 8 - SNP report signature: the VCEK's ECDSA-P384/SHA-384
    # signature over the report. Proves the report is genuine AMD hardware
    # output; from here on, the report's contents are trusted.
    if not verify_snp_report_signature(parsed.vcek, snp, failure):
        return ({}, failure)

    # Phase 9 - VMPL: the report must have been issued at VMPL 0, where the
    # HCL/paravisor and vTPM run. Proves it came from the firmware layer --
    # the guest runs at a higher VMPL and can never produce such a report.
    if not verify_vmpl(snp, failure):
        return ({}, failure)

    # Phase 10 - init-data binding (optional): PCR[8] must equal
    # sha256(32 zero bytes || expected init-data hash). Proves the init-data
    # delivered to the guest is the one we wanted.
    if not verify_init_data(init_data_hash, parsed.quote_pcrs, failure):
        return ({}, failure)

    # Phase 11 (eventlog replay) is not implemented: cc_eventlog is accepted
    # but ignored; see the TODO at the top of this module.

    # Phase 12 - claims assembly: build the claims map (policy, TCB,
    # platform info, measurement, PCRs) for keylime's policy layer. No
    # verification happens here; this is the output contract.
    claims = parse_claims(snp, attest, parsed.quote_pcrs)
    logger.info("az-snp-vtpm evidence verified successfully (evidence version %d)", parsed.version)
    return (claims, failure)
