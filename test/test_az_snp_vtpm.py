"""Unit tests for the az-snp-vtpm TEE evidence verifier."""

import base64
import dataclasses
import hashlib
import json
import logging
import os
import struct
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_modules import rfc2459

from keylime.failure import Component, Failure
from keylime.tee import az_snp_vtpm

CURDIR = os.path.dirname(os.path.abspath(__file__))
TESTDATA = os.path.join(CURDIR, "..", "test-data", "az_snp_vtpm")
# the per-generation ASK/ARK PEMs moved into the package as the bundled
# trust store (test-data keeps only the evidence fixtures)
ANCHOR_STORE = az_snp_vtpm.BUNDLED_ANCHOR_STORE

TRUST_ANCHORS = az_snp_vtpm.load_trust_anchors(ANCHOR_STORE)


def seed_anchor_cache(chains=None):
    """Seed the module's in-memory anchor cache with the hardcoded pairs.

    The tests use the bundled ASK/ARK PEM fixtures as the "KDS" so that no
    network access ever happens; resolve_trust_anchors() then serves them
    from the cache.
    """
    az_snp_vtpm.clear_anchor_cache()
    az_snp_vtpm._ANCHOR_CACHE.update(TRUST_ANCHORS if chains is None else chains)  # pylint: disable=protected-access


# Evidence nonces (extraData) of the trustee fixtures
REPORT_DATA_CHALLENGE = b"challenge"
REPORT_DATA_V2 = bytes.fromhex(
    "982f5c6e45df0ed3f10b6f60b02f0c8390e281300f3805e2279c16168cd6ae9aa398f647caa2338748cd0fd9f5f819ef"
)
REPORT_DATA_GENOA = bytes.fromhex(
    "0218488bae25d2509232bf676f1a66a30d7372add909109b36016ef136f2938ca05475f8b46094de6b64270ea35d950f"
)

# Known-good values asserted by trustee's own tests
EVIDENCE_V0_PCR0 = "e15c44796beabf46abcec7c57e590942041e47497e4ec27571c8b7664f48dced"
EVIDENCE_V2_PCR0 = "84275b2f4312cd4fc6cbe6b152ad3c3683e513d9f1e23c34fca160c8cca7a6a7"
EVIDENCE_GENOA_PCR0 = "afd689d0bb1c5f36f023fbaf574135f555a28a10c1f6b938d2a25e70c7783338"

INIT_DATA_HASH = bytes.fromhex("8505e4e25e50a27c5dc8147af88efbece627fbea55291911eff832d9ee127781")
INIT_DATA_PCR8 = bytes.fromhex("bddaccb9c52249e97a31baea61b7d91be8221a16e703d92148d04fb8e9c1dfdd")

TEE_COMPONENT = Component.TEE.value  # "tee_attestation"


def load_json(name):
    with open(os.path.join(TESTDATA, name), encoding="utf-8") as f:
        return json.load(f)


def event_ids(failure):
    """The full event ids (component.event_id) recorded in a Failure."""
    return [event.event_id for event in failure.events]


def derive_keylime_evidence_nonce(envelope):
    """Recompute the RCAR runtime-data digest of a keylime fixture envelope.

    The evidence nonce the guest quotes with is SHA-384 over the canonical
    JSON {"additional-evidence", "nonce", "tee-pubkey"} built from the KBS
    challenge and the session key (serde_json_canonicalizer: sorted keys,
    no whitespace).
    """
    data = envelope["data"]
    runtime_data = {
        "additional-evidence": "",
        "nonce": data["nonce"],
        "tee-pubkey": {
            "alg": "ECDH-ES+A256KW",
            "crv": "P-256",
            "kty": "EC",
            "x": data["tee-pubkey-x-b64"],
            "y": data["tee-pubkey-y-b64"],
        },
    }
    canonical = json.dumps(runtime_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha384(canonical.encode("utf-8")).digest()


def keylime_evidence(envelope):
    return envelope["data"]["tee-evidence"]["evidence"]


class VerifyAttestationTest(unittest.TestCase):
    """End-to-end verification, one positive test per fixture."""

    def verify(self, evidence, nonce, **kwargs):
        seed_anchor_cache()
        return az_snp_vtpm.verify_attestation(evidence, nonce, **kwargs)

    def test_local_fixture_v0(self):
        """The locally generated D-series envelope (v0 evidence) verifies end-to-end.

        Unlike the trustee fixtures, this one wraps a different (newer-TCB)
        Genoa report in the keylime D-series evidence envelope.
        """
        name = "evidence-v0-genoa-local.json"
        envelope = load_json(name)
        nonce = derive_keylime_evidence_nonce(envelope)
        claims, failure = self.verify(keylime_evidence(envelope), nonce)
        self.assertEqual(event_ids(failure), [], msg=str(failure.events))
        self.assertTrue(claims)
        # report_data claim is the hex of the quote nonce
        self.assertEqual(claims["report_data"], nonce.hex())
        self.assertEqual(len(claims["tpm"]), 24)

        # the envelope nonce is committed through the RCAR runtime-data
        # digest: a challenge derived from a tampered envelope must not
        # match the report_data committed at quote time
        tampered = json.loads(json.dumps(envelope))
        tampered["data"]["nonce"] = base64.b64encode(b"other-challenge").decode()
        _claims, failure = self.verify(keylime_evidence(tampered), derive_keylime_evidence_nonce(tampered))
        self.assertNotEqual(event_ids(failure), [])

    def test_trustee_evidence_v0(self):
        evidence = load_json("evidence-v0-milan.json")
        claims, failure = self.verify(evidence, REPORT_DATA_CHALLENGE)
        self.assertEqual(event_ids(failure), [])
        self.assertEqual(claims["report_data"], "6368616c6c656e6765")
        self.assertEqual(claims["tpm"]["pcr00"], EVIDENCE_V0_PCR0)

    def test_trustee_evidence_v1(self):
        evidence = load_json("evidence-v1-milan.json")
        claims, failure = self.verify(evidence, REPORT_DATA_CHALLENGE)
        self.assertEqual(event_ids(failure), [])
        self.assertEqual(claims["tpm"]["pcr00"], EVIDENCE_V0_PCR0)

    def test_trustee_evidence_v2(self):
        evidence = load_json("evidence-v2-milan.json")
        claims, failure = self.verify(evidence, REPORT_DATA_V2)
        self.assertEqual(event_ids(failure), [])
        self.assertEqual(claims["report_data"], REPORT_DATA_V2.hex())
        self.assertEqual(claims["tpm"]["pcr00"], EVIDENCE_V2_PCR0)

    def test_trustee_evidence_genoa(self):
        # genoa fixture is v0-shaped (byte arrays, PEM vcek) but Genoa-chained
        evidence = load_json("evidence-v0-genoa.json")
        self.assertNotIn("version", evidence)
        claims, failure = self.verify(evidence, REPORT_DATA_GENOA)
        self.assertEqual(event_ids(failure), [])
        self.assertEqual(claims["tpm"]["pcr00"], EVIDENCE_GENOA_PCR0)

    def test_init_data_binding(self):
        # sha256(0x00*32 || init_data_hash) == PCR[8] (trustee's known values).
        # Called directly: a true end-to-end init-data test would need a fresh
        # quote from a live vTPM -- changing PCR[8] in a fixture breaks the
        # signed pcrDigest (phase 3) and the quote cannot be re-signed without
        # the vTPM's private AK.
        self.assertTrue(az_snp_vtpm.verify_init_data(INIT_DATA_HASH, [INIT_DATA_PCR8] * 24, Failure(Component.TEE)))

    def test_init_data_binding_failure(self):
        evidence = load_json("evidence-v0-milan.json")
        pcrs = [bytes(p) for p in evidence["quote"]["pcrs"]]
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_init_data(INIT_DATA_HASH, pcrs, failure))
        self.assertIn(f"{TEE_COMPONENT}.init_data", event_ids(failure))

    def test_init_data_short_pcr_list(self):
        # a direct caller with a PCR list too short for PCR[8] fails cleanly
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_init_data(INIT_DATA_HASH, [INIT_DATA_PCR8] * 8, failure))
        self.assertIn(f"{TEE_COMPONENT}.init_data", event_ids(failure))

    def test_init_data_mismatch_end_to_end(self):
        # through the main entry point: a wrong expected init-data digest
        # must fail the whole verification (no fixture has a bound PCR[8],
        # so the positive case stays with the direct test above)
        envelope = load_json("evidence-v0-genoa-local.json")
        claims, failure = self.verify(
            keylime_evidence(envelope), derive_keylime_evidence_nonce(envelope), init_data_hash=bytes(32)
        )
        self.assertEqual(claims, {})
        self.assertIn(f"{TEE_COMPONENT}.init_data", event_ids(failure))

    def test_nonce_last_byte_mismatch(self):
        # flip only the last byte of the expected nonce: a comparison
        # weakened to a prefix would let this pass
        evidence = load_json("evidence-v2-milan.json")
        tampered = REPORT_DATA_V2[:-1] + bytes([REPORT_DATA_V2[-1] ^ 1])
        claims, failure = self.verify(evidence, tampered)
        self.assertEqual(claims, {})
        self.assertIn(f"{TEE_COMPONENT}.quote_nonce", event_ids(failure))

    def test_vcek_validity_frozen_clock(self):
        # the real _cert_within_validity against the fixture VCEK's window,
        # with the module clock frozen just outside it on both sides (the
        # dates are derived from the certificate, so the test follows a
        # refreshed fixture)
        evidence = load_json("evidence-v2-milan.json")
        vcek = az_snp_vtpm.parse_evidence(evidence).vcek
        for frozen in (vcek.not_valid_after_utc + timedelta(days=1), vcek.not_valid_before_utc - timedelta(days=1)):
            with self.subTest(frozen=frozen.isoformat()):

                class FrozenDatetime(datetime):
                    @classmethod
                    def now(cls, tz=None):
                        return cls(frozen.year, frozen.month, frozen.day, tzinfo=tz)

                with patch.object(az_snp_vtpm, "datetime", FrozenDatetime):
                    claims, failure = self.verify(evidence, REPORT_DATA_V2)
                self.assertEqual(claims, {})
                self.assertIn(f"{TEE_COMPONENT}.vcek_validity", event_ids(failure))

    def test_claims_contract_v2_milan(self):
        # pin the complete claims map: it is the policy layer's input and
        # every key and value is part of the output contract
        evidence = load_json("evidence-v2-milan.json")
        claims, failure = self.verify(evidence, REPORT_DATA_V2)
        self.assertEqual(event_ids(failure), [], msg=str(failure.events))
        self.assertEqual(
            claims,
            {
                "policy_abi_major": "0",
                "policy_abi_minor": "31",
                "policy_smt_allowed": "true",
                "policy_migrate_ma": "false",
                "policy_debug_allowed": "false",
                "policy_single_socket": "false",
                "reported_tcb_bootloader": "4",
                "reported_tcb_tee": "0",
                "reported_tcb_snp": "24",
                "reported_tcb_microcode": "219",
                "platform_tsme_enabled": "false",
                "platform_smt_enabled": "true",
                "measurement": "WwzmStHB9jddvaX3YLmFJsobz5G4GVCRr8KOewJCUdaP4y4FrzQEjWYHZ4zSMoP/",
                "report_data": REPORT_DATA_V2.hex(),
                "init_data": "00" * 32,
                "tpm": {
                    "pcr00": "84275b2f4312cd4fc6cbe6b152ad3c3683e513d9f1e23c34fca160c8cca7a6a7",
                    "pcr01": "d858797eb6a5e71c4524945cd454e4e01cda4a7cb530b69d4e349fcd6de70691",
                    "pcr02": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                    "pcr03": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
                    "pcr04": "7461d6b7d5922dbd8fd58bfaac8f53c3380f01708bd1593ef367e3371791e717",
                    "pcr05": "fac76dae26e12de39777bdfdbd8e137595e6f52a6ccecb4aa2b22134fb654e3d",
                    "pcr06": "964e9870f9bf29d7e9df42e9e4c70f59b27f489e086ba2ee6e8d62a2b0bb6131",
                    "pcr07": "f014e5cbfa297ee787a976abc51bc1d67e23e1b9e4a60128a1106dd0adef0c5b",
                    "pcr08": "00" * 32,
                    "pcr09": "630dc838b500d34ba7439095443b2d06d915f5acabf4f6d9ea7f49c78a8af3f9",
                    "pcr10": "b58de4bda56e86736246ec69bb7423516c98b4ef0dcb16d56b334ed3c7fbf523",
                    "pcr11": "00" * 32,
                    "pcr12": "f1a142c53586e7e2223ec74e5f4d1a4942956b1fd9ac78fafcdf85117aa345da",
                    "pcr13": "00" * 32,
                    "pcr14": "306f9d8b94f17d93dc6e7cf8f5c79d652eb4c6c4d13de2dddc24af416e13ecaf",
                    "pcr15": "00" * 32,
                    "pcr16": "00" * 32,
                    "pcr17": "ff" * 32,
                    "pcr18": "ff" * 32,
                    "pcr19": "ff" * 32,
                    "pcr20": "ff" * 32,
                    "pcr21": "ff" * 32,
                    "pcr22": "ff" * 32,
                    "pcr23": "00" * 32,
                },
            },
        )

    def test_cc_eventlog_ignored(self):
        """v2 evidence carrying a cc_eventlog must not fail (replay not implemented)."""
        evidence = load_json("evidence-v2-milan.json")
        evidence["cc_eventlog"] = "aGVsbG8="  # non-empty, would need replay
        _claims, failure = self.verify(evidence, REPORT_DATA_V2)
        self.assertEqual(event_ids(failure), [])

    def test_missing_trust_anchors(self):
        # an anchor store with no usable chain -> fail closed
        envelope = load_json("evidence-v0-genoa-local.json")
        az_snp_vtpm.clear_anchor_cache()
        with tempfile.TemporaryDirectory() as empty:
            with patch.object(az_snp_vtpm.config, "get", return_value=empty):
                claims, failure = az_snp_vtpm.verify_attestation(
                    keylime_evidence(envelope), derive_keylime_evidence_nonce(envelope)
                )
        self.assertEqual(claims, {})
        self.assertIn(f"{TEE_COMPONENT}.missing_trust_anchors", event_ids(failure))


class ParseEvidenceTest(unittest.TestCase):
    """Phase 0 - version detection, latest-first."""

    def test_version_detection_order_latest_to_oldest(self):
        # the parsers must be attempted v2 -> v1 -> v0 (trustee's enum order)
        calls = []

        def wrap(parser, version):
            def wrapped(evidence):
                calls.append(version)
                return parser(evidence)

            return wrapped

        with patch.multiple(
            az_snp_vtpm,
            _parse_evidence_v2=wrap(az_snp_vtpm._parse_evidence_v2, 2),  # pylint: disable=protected-access
            _parse_evidence_v1=wrap(az_snp_vtpm._parse_evidence_v1, 1),  # pylint: disable=protected-access
            _parse_evidence_v0=wrap(az_snp_vtpm._parse_evidence_v0, 0),  # pylint: disable=protected-access
        ):
            az_snp_vtpm.parse_evidence(load_json("evidence-v0-milan.json"))
        self.assertEqual(calls, [2, 1, 0])

    def test_v2_wins_over_v1(self):
        # a v1-shaped dict also carries the optional v2-only cc_eventlog
        # field; with version == 2 it must parse as v2
        evidence = load_json("evidence-v2-milan.json")
        parsed = az_snp_vtpm.parse_evidence(evidence)
        self.assertEqual(parsed.version, 2)

    def test_v0_ignores_unknown_fields(self):
        # like trustee's serde, the v0 shape ignores a stray "version" key
        evidence = load_json("evidence-v0-milan.json")
        evidence["version"] = 1
        parsed = az_snp_vtpm.parse_evidence(evidence)
        self.assertEqual(parsed.version, 0)

    def test_v0(self):
        parsed = az_snp_vtpm.parse_evidence(load_json("evidence-v0-milan.json"))
        self.assertEqual(parsed.version, 0)
        self.assertEqual(len(parsed.quote_message), 122)

    def test_v1(self):
        parsed = az_snp_vtpm.parse_evidence(load_json("evidence-v1-milan.json"))
        self.assertEqual(parsed.version, 1)

    def test_v2(self):
        parsed = az_snp_vtpm.parse_evidence(load_json("evidence-v2-milan.json"))
        self.assertEqual(parsed.version, 2)
        self.assertIsNone(parsed.cc_eventlog)

    def test_unknown_version(self):
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_evidence({"version": 99, "tpm_quote": {}})

    def test_garbage(self):
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_evidence({})


class HclReportTest(unittest.TestCase):
    """Phase 0 - HCL container parsing."""

    def setUp(self):
        # the trustee v0 evidence carries the same 2600-byte HCL container
        # (container version 1, SNP report v2) as trustee's hcl-report.bin
        self.report = bytes(load_json("evidence-v0-milan.json")["report"])
        self.hcl = az_snp_vtpm.parse_hcl_report(self.report)
        self.snp = az_snp_vtpm.parse_snp_report(self.hcl.snp_report)

    def test_header(self):
        magic, version, report_size, request_type, status, _ = struct.unpack_from("<6I", self.report, 0)
        self.assertEqual(magic, az_snp_vtpm.HCL_HEADER_MAGIC)
        self.assertIn(version, (1, 2))
        self.assertEqual(request_type, 2)
        self.assertEqual(status, 0)
        self.assertEqual(report_size, 2346)

    def test_container_versions_accepted(self):
        # trustee fixtures use version 1, the keylime/genoa captures version 2
        for version in (1, 2):
            report = bytearray(self.report)
            struct.pack_into("<I", report, 4, version)
            az_snp_vtpm.parse_hcl_report(bytes(report))

    def test_ak_pub(self):
        self.assertIsNotNone(self.hcl.ak_pub)

    def test_claims(self):
        self.assertIn("keys", self.hcl.claims)

    def test_bad_magic(self):
        wrong = bytearray(self.report)
        wrong[0] ^= 0xFF
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(bytes(wrong))

    def test_unsupported_container_version(self):
        wrong = bytearray(self.report)
        struct.pack_into("<I", wrong, 4, 99)
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(bytes(wrong))

    def test_truncated(self):
        with self.assertRaises(ValueError) as ctx:
            az_snp_vtpm.parse_hcl_report(self.report[:100])
        # the error must state the expected minimum length
        self.assertIn(str(az_snp_vtpm.HCL_RUNTIME_DATA_OFFSET), str(ctx.exception))

    def test_wrong_request_type(self):
        wrong = bytearray(self.report)
        struct.pack_into("<I", wrong, 12, 99)
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(bytes(wrong))

    def test_runtime_bad_version(self):
        wrong = bytearray(self.report)
        struct.pack_into("<I", wrong, az_snp_vtpm.HCL_RUNTIME_DATA_OFFSET + 4, 99)
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(bytes(wrong))

    def test_runtime_bad_report_type(self):
        wrong = bytearray(self.report)
        struct.pack_into("<I", wrong, az_snp_vtpm.HCL_RUNTIME_DATA_OFFSET + 8, 99)
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(bytes(wrong))

    def test_runtime_bad_hash_type(self):
        wrong = bytearray(self.report)
        struct.pack_into("<I", wrong, az_snp_vtpm.HCL_RUNTIME_DATA_OFFSET + 12, 99)
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(bytes(wrong))

    def test_runtime_size_mismatch(self):
        # data_size disagrees with header size + claim_size
        wrong = bytearray(self.report)
        struct.pack_into("<I", wrong, az_snp_vtpm.HCL_RUNTIME_DATA_OFFSET, 12345)
        with self.assertRaises(ValueError) as ctx:
            az_snp_vtpm.parse_hcl_report(bytes(wrong))
        self.assertIn("data_size", str(ctx.exception))

    def test_runtime_truncated_data(self):
        # data_size is consistent with claim_size, but larger than the bytes present
        wrong = bytearray(self.report)
        struct.pack_into(
            "<I", wrong, az_snp_vtpm.HCL_RUNTIME_DATA_OFFSET, az_snp_vtpm.HCL_RUNTIME_DATA_HEADER_SIZE + 10**6
        )
        struct.pack_into("<I", wrong, az_snp_vtpm.HCL_RUNTIME_DATA_OFFSET + 16, 10**6)
        with self.assertRaises(ValueError) as ctx:
            az_snp_vtpm.parse_hcl_report(bytes(wrong))
        self.assertIn("truncated", str(ctx.exception))

    def test_user_data_invalid_hex(self):
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(MalformedEvidenceTest.synthetic_hcl(b'{"keys": [], "user-data": "zz"}'))

    def test_snp_report_wrong_length(self):
        with self.assertRaises(ValueError) as ctx:
            az_snp_vtpm.parse_snp_report(self.hcl.snp_report[:-1])
        self.assertIn(str(az_snp_vtpm.SNP_REPORT_SIZE), str(ctx.exception))


class TpmAttestTest(unittest.TestCase):
    """Phase 0 - TPMS_ATTEST parsing."""

    def setUp(self):
        evidence = load_json("evidence-v0-milan.json")
        self.message = bytes(evidence["quote"]["message"])
        self.attest = az_snp_vtpm.parse_tpm_attest(self.message)

    def test_extra_data(self):
        self.assertEqual(self.attest.extra_data, REPORT_DATA_CHALLENGE)

    def test_pcr_digest(self):
        evidence = load_json("evidence-v0-milan.json")
        pcrs = b"".join(bytes(p) for p in evidence["quote"]["pcrs"])
        self.assertEqual(hashlib.sha256(pcrs).digest(), self.attest.pcr_digest)

    def test_pcr_select(self):
        self.assertEqual(self.attest.pcr_select_hash_algs, [az_snp_vtpm.TPM_ALG_SHA256])
        self.assertEqual(self.attest.pcr_select_bitmap, b"\xff\xff\xff")

    def test_full_consumption(self):
        # parser must consume the message exactly; extra trailing byte fails
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_tpm_attest(self.message + b"\x00")

    def test_bad_magic(self):
        wrong = bytearray(self.message)
        wrong[0] ^= 0xFF
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_tpm_attest(bytes(wrong))


class VerifyTpmPcrsTest(unittest.TestCase):
    """Phase 3 - the PCR digest check, called directly."""

    def setUp(self):
        # valid-first: the unmodified fixture must pass before any mutation
        self.parsed = az_snp_vtpm.parse_evidence(load_json("evidence-v0-milan.json"))
        self.attest = az_snp_vtpm.parse_tpm_attest(self.parsed.quote_message)
        self.assertTrue(az_snp_vtpm.verify_tpm_pcrs(self.parsed.quote_pcrs, self.attest, Failure(Component.TEE)))

    def test_wrong_pcr_length(self):
        pcrs = list(self.parsed.quote_pcrs)
        pcrs[0] = pcrs[0][:-1]  # 31 bytes instead of 32
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_tpm_pcrs(pcrs, self.attest, failure))
        self.assertIn(f"{TEE_COMPONENT}.pcr_digest", event_ids(failure))

    def test_wrong_bank(self):
        # a single SHA-1 bank instead of SHA-256
        attest = dataclasses.replace(self.attest, pcr_select_hash_algs=[0x0004])
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_tpm_pcrs(self.parsed.quote_pcrs, attest, failure))
        self.assertIn(f"{TEE_COMPONENT}.pcr_digest", event_ids(failure))

    def test_two_banks(self):
        attest = dataclasses.replace(self.attest, pcr_select_hash_algs=[az_snp_vtpm.TPM_ALG_SHA256, 0x0004])
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_tpm_pcrs(self.parsed.quote_pcrs, attest, failure))
        self.assertIn(f"{TEE_COMPONENT}.pcr_digest", event_ids(failure))


class ReportDataHashTypeTest(unittest.TestCase):
    """Phase 4 - the claims-to-report_data binding honors the runtime data hash type."""

    def setUp(self):
        # valid-first: the real fixture binds under SHA-256
        ev = load_json("evidence-v0-milan.json")
        self.hcl_orig = az_snp_vtpm.parse_hcl_report(bytes(ev["report"]))
        self.snp_orig = az_snp_vtpm.parse_snp_report(self.hcl_orig.snp_report)
        self.claims = self.hcl_orig.claims_bytes
        self.assertTrue(az_snp_vtpm.verify_report_data(self.hcl_orig, self.snp_orig, Failure(Component.TEE)))

    def check(self, hash_type, hash_fn):
        hcl = az_snp_vtpm.parse_hcl_report(MalformedEvidenceTest.synthetic_hcl(self.claims, hash_type))
        self.assertEqual(hcl.hash_type, hash_type)
        # a report_data carrying the matching digest binds
        digest = hash_fn(self.claims).digest()
        snp = dataclasses.replace(self.snp_orig, report_data=digest + b"\x00" * (64 - len(digest)))
        self.assertTrue(az_snp_vtpm.verify_report_data(hcl, snp, Failure(Component.TEE)))
        # a digest of a different algorithm must not bind
        wrong = hashlib.sha256(self.claims).digest()
        snp_wrong = dataclasses.replace(self.snp_orig, report_data=wrong + b"\x00" * 32)
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_report_data(hcl, snp_wrong, failure))
        self.assertIn(f"{TEE_COMPONENT}.hcl_binding", event_ids(failure))

    def test_sha384(self):
        self.check(az_snp_vtpm.HCL_RUNTIME_DATA_HASH_TYPE_SHA384, hashlib.sha384)

    def test_sha512(self):
        self.check(az_snp_vtpm.HCL_RUNTIME_DATA_HASH_TYPE_SHA512, hashlib.sha512)


class PhaseFailureTest(unittest.TestCase):
    """Per-phase negative tests: one bit-flip per check."""

    def setUp(self):
        seed_anchor_cache()
        self.envelope = load_json("evidence-v0-genoa-local.json")
        self.evidence = keylime_evidence(self.envelope)
        self.nonce = derive_keylime_evidence_nonce(self.envelope)
        # valid-first: the unmodified fixture must verify before any mutation
        self.assert_valid_baseline()

    def assert_valid_baseline(self):
        claims, failure = az_snp_vtpm.verify_attestation(json.loads(json.dumps(self.evidence)), self.nonce)
        self.assertEqual(event_ids(failure), [], msg=str(failure.events))
        self.assertTrue(claims, msg=str(failure.events))

    def fail_with(self, code, evidence=None, nonce=None):
        failure = Failure(Component.TEE)
        claims, failure = az_snp_vtpm.verify_attestation(
            evidence if evidence is not None else json.loads(json.dumps(self.evidence)),
            nonce if nonce is not None else self.nonce,
        )
        self.assertEqual(claims, {})
        self.assertIn(f"{TEE_COMPONENT}.{code}", event_ids(failure), msg=str(failure.events))
        return failure

    def test_quote_signature(self):
        self.evidence["quote"]["signature"][0] ^= 1
        self.fail_with("quote_signature")

    def test_tampered_ak_pub(self):
        # corrupt a byte inside the HCLAkPub modulus (JSON stays valid, the
        # key changes) -> the quote signature no longer verifies
        report = bytearray(self.evidence["report"])
        claims_start = az_snp_vtpm.HCL_RUNTIME_DATA_OFFSET + az_snp_vtpm.HCL_RUNTIME_DATA_HEADER_SIZE
        n_offset = bytes(report).find(b'"n":"', claims_start) + len('"n":"')
        report[n_offset] = ord("A") if report[n_offset] != ord("A") else ord("B")
        with patch.dict(self.evidence, {"report": list(report)}):
            self.fail_with("quote_signature")

    def test_quote_nonce(self):
        self.fail_with("quote_nonce", nonce=self.nonce[::-1])

    def test_pcr_digest(self):
        self.evidence["quote"]["pcrs"][0][0] ^= 1
        self.fail_with("pcr_digest")

    def test_pcr_count(self):
        self.evidence["quote"]["pcrs"] = self.evidence["quote"]["pcrs"][:23]
        self.fail_with("pcr_digest")

    def test_hcl_binding(self):
        # flip a byte inside the runtime claims JSON
        report = bytearray(self.evidence["report"])
        report[0x06E0] += 1
        with patch.dict(self.evidence, {"report": list(report)}):
            self.fail_with("hcl_binding")

    def test_user_data_v2_only(self):
        # v2 evidence with a wrong nonce fails the user-data check (checked
        # directly: through verify_attestation the quote_nonce phase would
        # fire first)
        evidence = load_json("evidence-v2-milan.json")
        hcl = az_snp_vtpm.parse_hcl_report(az_snp_vtpm.parse_evidence(evidence).hcl_report)
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_user_data(hcl, REPORT_DATA_V2[::-1], failure, 2))
        self.assertIn(f"{TEE_COMPONENT}.user_data", event_ids(failure))
        # and the correct nonce passes
        self.assertTrue(az_snp_vtpm.verify_user_data(hcl, REPORT_DATA_V2, Failure(Component.TEE), 2))

    def test_user_data_gate_skips_old_versions(self):
        # the version gate lives inside the function: v0/v1 evidence with a
        # wrong nonce is skipped, not failed
        evidence = load_json("evidence-v2-milan.json")
        hcl = az_snp_vtpm.parse_hcl_report(az_snp_vtpm.parse_evidence(evidence).hcl_report)
        for version in (0, 1):
            with self.subTest(version=version):
                self.assertTrue(
                    az_snp_vtpm.verify_user_data(hcl, REPORT_DATA_V2[::-1], Failure(Component.TEE), version)
                )

    def test_user_data_not_checked_for_v0(self):
        # v0 user-data holds a stale boot-time value; it must not be checked
        # (the local fixture's user-data is "my-fixed-test-nonce")
        envelope = load_json("evidence-v0-genoa-local.json")
        hcl = az_snp_vtpm.parse_hcl_report(bytes(envelope["data"]["tee-evidence"]["evidence"]["report"]))
        self.assertNotEqual(hcl.user_data[:48], derive_keylime_evidence_nonce(envelope))
        _claims, failure = az_snp_vtpm.verify_attestation(
            keylime_evidence(envelope), derive_keylime_evidence_nonce(envelope)
        )
        self.assertEqual(event_ids(failure), [])

    def test_vcek_wrong_chain(self):
        # Genoa VCEK against Milan-only anchors fails: seed only the Milan
        # pair so the Genoa chain is unavailable
        genoa = load_json("evidence-v0-genoa.json")
        seed_anchor_cache({"milan": TRUST_ANCHORS["milan"]})
        claims, failure = az_snp_vtpm.verify_attestation(genoa, REPORT_DATA_GENOA)
        self.assertEqual(claims, {})
        self.assertIn(f"{TEE_COMPONENT}.vcek_chain", event_ids(failure))

    def test_vcek_mixed_generation_rejected(self):
        """A VCEK from another generation must not validate against the report's chain."""
        # baseline: the untouched genoa fixture verifies (valid-first)
        genoa = load_json("evidence-v0-genoa.json")
        seed_anchor_cache()
        _claims, failure = az_snp_vtpm.verify_attestation(genoa, REPORT_DATA_GENOA)
        self.assertEqual(event_ids(failure), [], msg=str(failure.events))

        # swap in the Milan VCEK: the report is Genoa, so the pinned chain
        # must reject it, and the issuer/report mismatch must be logged
        with open(os.path.join(TESTDATA, "vcek.pem"), encoding="utf-8") as f:
            genoa["vcek"] = f.read()
        seed_anchor_cache()
        with self.assertLogs("keylime.az_snp_vtpm", level=logging.WARNING):
            claims, failure = az_snp_vtpm.verify_attestation(genoa, REPORT_DATA_GENOA)
        self.assertEqual(claims, {})
        self.assertIn(f"{TEE_COMPONENT}.vcek_chain", event_ids(failure))

    def test_vcek_expired(self):
        evidence = json.loads(json.dumps(self.evidence))
        with patch.object(az_snp_vtpm, "_cert_within_validity", return_value=False):
            claims, failure = az_snp_vtpm.verify_attestation(evidence, self.nonce)
        self.assertEqual(claims, {})
        self.assertIn(f"{TEE_COMPONENT}.vcek_validity", event_ids(failure))

    def test_vcek_tcb_oid_mismatch(self):
        # container offset 0x1a6 == payload 0x186 == reported_tcb snp byte
        # (trustee's own wrong_report[0x01a6] corruption)
        report = bytearray(self.evidence["report"])
        report[0x01A6] = 0
        with patch.dict(self.evidence, {"report": list(report)}):
            self.fail_with("vcek_oid_mismatch")

    def test_vcek_chip_id_mismatch(self):
        # container offset 0x1c0 == payload 0x1a0 == chip_id start
        report = bytearray(self.evidence["report"])
        report[0x01C0] ^= 1
        with patch.dict(self.evidence, {"report": list(report)}):
            self.fail_with("vcek_chip_id")

    def test_vcek_chip_id_deep_byte_mismatch(self):
        # flip a byte in the middle of the 64-byte chip_id: a comparison
        # weakened to a prefix would let this pass
        report = bytearray(self.evidence["report"])
        report[0x01C0 + 32] ^= 1
        with patch.dict(self.evidence, {"report": list(report)}):
            self.fail_with("vcek_chip_id")

    def test_key_info_vlek_rejected(self):
        # signing-key type VLEK (key_info bits 2-4) is rejected at parse
        # time, before any signature check runs
        report = bytearray(self.evidence["report"])
        struct.pack_into("<I", report, az_snp_vtpm.SNP_REPORT_OFFSET + az_snp_vtpm.SNP_REPORT_KEY_INFO_OFFSET, 1 << 2)
        with patch.dict(self.evidence, {"report": list(report)}):
            self.fail_with("hcl_report")

    def test_key_info_masked_report_rejected(self):
        # MASK_CHIP_KEY (key_info bit 1): an unsigned report is rejected
        report = bytearray(self.evidence["report"])
        struct.pack_into("<I", report, az_snp_vtpm.SNP_REPORT_OFFSET + az_snp_vtpm.SNP_REPORT_KEY_INFO_OFFSET, 0b10)
        with patch.dict(self.evidence, {"report": list(report)}):
            self.fail_with("hcl_report")

    def test_report_missing_cpuid(self):
        """A report without CPUID (version 2) fails closed with an honest error.

        Reaching phase 0's parse is enough: parsing runs before any signature
        check, so zeroing the CPUID bytes yields the generation error rather
        than a misleading VCEK-chain failure.
        """
        evidence = json.loads(json.dumps(self.evidence))
        report = bytearray(evidence["report"])
        off = az_snp_vtpm.SNP_REPORT_OFFSET
        report[off + 0x188] = 0
        report[off + 0x189] = 0
        evidence["report"] = list(report)
        claims, failure = az_snp_vtpm.verify_attestation(evidence, self.nonce)
        self.assertEqual(claims, {}, msg=str(failure.events))
        self.assertIn(f"{TEE_COMPONENT}.hcl_report", event_ids(failure), msg=str(failure.events))
        self.assertTrue(any("CPUID" in event.context for event in failure.events), msg=str(failure.events))

    def test_vcek_missing_oid_extension(self):
        """A VCEK missing an extension must fail, not pass silently."""
        real_get = az_snp_vtpm._get_oid_value  # pylint: disable=protected-access

        def drop(oid):
            def get(cert, wanted):
                return None if wanted == oid else real_get(cert, wanted)

            return get

        for oid, code in (
            (az_snp_vtpm.HW_ID_OID, "vcek_chip_id"),
            (az_snp_vtpm.UCODE_SPL_OID, "vcek_oid_mismatch"),
        ):
            with self.subTest(oid=oid):
                with patch.object(az_snp_vtpm, "_get_oid_value", side_effect=drop(oid)):
                    claims, failure = az_snp_vtpm.verify_attestation(json.loads(json.dumps(self.evidence)), self.nonce)
                self.assertEqual(claims, {}, msg=str(failure.events))
                self.assertIn(f"{TEE_COMPONENT}.{code}", event_ids(failure), msg=str(failure.events))
                self.assertTrue(
                    any("has no usable" in event.context for event in failure.events),
                    msg=str(failure.events),
                )

    def test_report_signature(self):
        # flip a byte inside the SNP report signature area (container 0x2c0)
        report = bytearray(self.evidence["report"])
        report[0x02C0] ^= 1
        with patch.dict(self.evidence, {"report": list(report)}):
            self.fail_with("report_signature")

    def test_vmpl(self):
        # VMPL sits inside the VCEK-signed region, so flipping it in the raw
        # report breaks the signature check first; exercise the check itself
        report = bytes(self.evidence["report"])
        snp = az_snp_vtpm.parse_snp_report(az_snp_vtpm.parse_hcl_report(report).snp_report)
        self.assertEqual(snp.vmpl, 0)
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_vmpl(dataclasses.replace(snp, vmpl=1), failure))
        self.assertIn(f"{TEE_COMPONENT}.vmpl", event_ids(failure))


class DuplicatedExtensionTest(unittest.TestCase):
    """A duplicated extension OID must fail closed, not raise (finding F4).

    Extension parsing in cryptography is lazy, so a certificate with a
    duplicated extension loads fine and only raises when an extension is
    accessed -- exactly the condition _get_oid_value must contain. The
    crafted certificate's signature is broken by the surgery, so the test
    exercises the phase function directly (an end-to-end path would need
    an ASK-signed certificate, i.e. AMD's key).
    """

    @staticmethod
    def vcek_with_duplicated_extension(oid):
        """Rebuild the v2-milan fixture VCEK with one extension duplicated."""
        evidence = load_json("evidence-v2-milan.json")
        der = az_snp_vtpm._b64_decode_nopad(evidence["vcek"])  # pylint: disable=protected-access
        cert, _ = der_decoder.decode(der, asn1Spec=rfc2459.Certificate())
        exts = cert["tbsCertificate"]["extensions"]
        target = None
        for ext in exts:
            if str(ext["extnID"]) == oid:
                target = ext
                break
        assert target is not None, f"extension {oid} not found in the fixture VCEK"
        exts.append(target)
        return x509.load_der_x509_certificate(der_encoder.encode(cert))

    def setUp(self):
        evidence = load_json("evidence-v2-milan.json")
        parsed = az_snp_vtpm.parse_evidence(evidence)
        hcl = az_snp_vtpm.parse_hcl_report(parsed.hcl_report)
        self.snp = az_snp_vtpm.parse_snp_report(hcl.snp_report)

    def test_duplicated_extension_fails_closed(self):
        # a duplicated extension OID anywhere in the certificate makes the
        # lazy extensions block raise DuplicateExtension on first access,
        # regardless of which OID is requested: phase 7 always fails at
        # its first lookup (the chip id) and must fail closed, not raise
        for oid in (az_snp_vtpm.HW_ID_OID, az_snp_vtpm.UCODE_SPL_OID):
            with self.subTest(oid=oid):
                cert = self.vcek_with_duplicated_extension(oid)
                failure = Failure(Component.TEE)
                self.assertFalse(az_snp_vtpm.verify_vcek_oids(cert, self.snp, failure))
                self.assertIn(f"{TEE_COMPONENT}.vcek_chip_id", event_ids(failure))


class TrustAnchorsTest(unittest.TestCase):
    def test_load_all_generations(self):
        chains = az_snp_vtpm.load_trust_anchors(ANCHOR_STORE)
        self.assertEqual(set(chains), {"milan", "genoa", "turin"})

    def test_single_generation_directory(self):
        with tempfile.TemporaryDirectory() as store:
            with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as src:
                with open(os.path.join(store, "genoa_ask_ark.pem"), "wb") as dst:
                    dst.write(src.read())
            chains = az_snp_vtpm.load_trust_anchors(store)
        self.assertEqual(set(chains), {"genoa"})

    def test_single_file_rejected(self):
        # the store must be a directory, not a single PEM file
        with self.assertRaises(ValueError):
            az_snp_vtpm.load_trust_anchors(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"))

    def test_unparseable_file_skipped(self):
        """A corrupt anchor file is skipped with a warning, not a crash."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.pem")
            with open(bad, "wb") as f:
                f.write(b"this is not a certificate bundle")
            with open(os.path.join(tmp, "zzcopy.pem"), "wb") as f:
                with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as g:
                    f.write(g.read())
            with self.assertLogs("keylime.az_snp_vtpm", level=logging.WARNING):
                chains = az_snp_vtpm.load_trust_anchors(tmp)
        self.assertEqual(set(chains), {"genoa"})


class BundledAnchorTest(unittest.TestCase):
    """The bundled trust store is pinned: any change must be a conscious edit.

    The sha256 of each bundled anchor is recorded here so that refreshing a
    chain (see keylime/tee/amd_cert_store/README.md) always shows up as a
    test failure until the pin is updated alongside the file.
    """

    PINNED_SHA256 = {
        "milan": "cc871f0d2294176386175d9b5b962e18556b15ec13f55f8698b5f7a07aebf0c7",
        "genoa": "7397ae50f4bac4699393121cf7ce9e72bac49f9f7b8c524be8df97e59ca151e3",
        "turin": "34251ef16c414387e2bf36a69b675329156361e6e8113241209e46ebbd6da93f",
    }

    def test_bundled_anchors_are_pinned(self):
        for generation, digest in self.PINNED_SHA256.items():
            with open(os.path.join(ANCHOR_STORE, f"{generation}_ask_ark.pem"), "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(
                actual,
                digest,
                f"the bundled {generation} ASK/ARK chain changed; if intentional, refresh it "
                "per amd_cert_store/README.md and update this pin in the same commit",
            )


class ClaimsTest(unittest.TestCase):
    """Phase 12 - claims content."""

    def test_claims(self):
        evidence = load_json("evidence-v2-milan.json")
        seed_anchor_cache()
        claims, failure = az_snp_vtpm.verify_attestation(evidence, REPORT_DATA_V2)
        self.assertEqual(event_ids(failure), [])
        self.assertEqual(claims["report_data"], REPORT_DATA_V2.hex())
        self.assertEqual(claims["init_data"], evidence["tpm_quote"]["pcrs"][8])
        self.assertEqual(len(claims["tpm"]), 24)
        for index, pcr in enumerate(evidence["tpm_quote"]["pcrs"]):
            self.assertEqual(claims["tpm"][f"pcr{index:02d}"], pcr)
        # trustee emits policy/platform fields as strings
        for key in ("policy_abi_major", "reported_tcb_snp", "platform_smt_enabled"):
            self.assertIsInstance(claims[key], str)
        self.assertIn(claims["policy_debug_allowed"], ("true", "false"))

    def test_short_pcr_list(self):
        # a direct caller with a PCR list too short for PCR[8] raises cleanly
        evidence = load_json("evidence-v2-milan.json")
        parsed = az_snp_vtpm.parse_evidence(evidence)
        hcl = az_snp_vtpm.parse_hcl_report(parsed.hcl_report)
        snp = az_snp_vtpm.parse_snp_report(hcl.snp_report)
        attest = az_snp_vtpm.parse_tpm_attest(parsed.quote_message)
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_claims(snp, attest, parsed.quote_pcrs[:8])


class LoggingTest(unittest.TestCase):
    """The plugin emits debug-level traces per phase."""

    def test_debug_traces(self):
        envelope = load_json("evidence-v0-genoa-local.json")
        nonce = derive_keylime_evidence_nonce(envelope)
        seed_anchor_cache()
        with self.assertLogs("keylime.az_snp_vtpm", level=logging.DEBUG) as captured:
            _claims, failure = az_snp_vtpm.verify_attestation(keylime_evidence(envelope), nonce)
            self.assertEqual(event_ids(failure), [])
        messages = "\n".join(captured.output)
        for fragment in ("Evidence parsed as version", "HCL header:", "TPMS_ATTEST:", "VCEK validated"):
            self.assertIn(fragment, messages)


class TurinTcbTest(unittest.TestCase):
    """Generation-aware reported_tcb decoding (AMD ABI #56860 section 2.2).

    The TCB byte layout is generation-dependent: Milan/Genoa use
    [bootloader, tee, reserved x4, snp, microcode]; Turin uses
    [fmc, bootloader, tee, snp, reserved x3, microcode].
    """

    @staticmethod
    def snp_with_cpuid(family, model, tcb=(10, 11, 12, 13, 0, 0, 15, 14)):
        envelope = load_json("evidence-v0-genoa-local.json")
        report = bytearray(bytes(envelope["data"]["tee-evidence"]["evidence"]["report"]))
        snp = bytearray(
            report[az_snp_vtpm.SNP_REPORT_OFFSET : az_snp_vtpm.SNP_REPORT_OFFSET + az_snp_vtpm.SNP_REPORT_SIZE]
        )
        snp[0x188] = family
        snp[0x189] = model
        snp[0x180:0x188] = bytes(tcb)
        return az_snp_vtpm.parse_snp_report(bytes(snp))

    def test_generation_detection(self):
        self.assertEqual(self.snp_with_cpuid(0x19, 0x01).generation, "milan")
        self.assertEqual(self.snp_with_cpuid(0x19, 0x11).generation, "genoa")
        self.assertEqual(self.snp_with_cpuid(0x1A, 0x01).generation, "turin")
        # v2 reports carry no CPUID (reserved zeros): the generation cannot
        # be established, so it is refused instead of guessed
        with self.assertRaises(ValueError):
            self.snp_with_cpuid(0x00, 0x00)

    def test_unknown_family_rejected(self):
        with self.assertRaises(ValueError):
            self.snp_with_cpuid(0x42, 0x01)

    def test_legacy_tcb_layout(self):
        snp = self.snp_with_cpuid(0x19, 0x11)  # Genoa
        self.assertIsNone(snp.tcb_fmc)
        self.assertEqual((snp.tcb_bootloader, snp.tcb_tee, snp.tcb_snp, snp.tcb_microcode), (10, 11, 15, 14))

    def test_turin_tcb_layout(self):
        snp = self.snp_with_cpuid(0x1A, 0x01)  # Turin
        self.assertEqual(
            (snp.tcb_fmc, snp.tcb_bootloader, snp.tcb_tee, snp.tcb_snp, snp.tcb_microcode), (10, 11, 12, 13, 14)
        )

    def test_turin_oid_check(self):
        """The VCEK OID cross-check must use the Turin byte mapping."""
        snp = self.snp_with_cpuid(0x1A, 0x01)
        turin_values = {
            az_snp_vtpm.HW_ID_OID: snp.chip_id,
            az_snp_vtpm.UCODE_SPL_OID: b"\x02\x01\x0e",  # 14
            az_snp_vtpm.SNP_SPL_OID: b"\x02\x01\x0d",  # 13
            az_snp_vtpm.TEE_SPL_OID: b"\x02\x01\x0c",  # 12
            az_snp_vtpm.LOADER_SPL_OID: b"\x02\x01\x0b",  # 11
            az_snp_vtpm.FMC_SPL_OID: b"\x02\x01\x0a",  # 10
        }
        with patch.object(az_snp_vtpm, "_get_oid_value", side_effect=lambda cert, oid: turin_values.get(oid)):
            self.assertTrue(az_snp_vtpm.verify_vcek_oids(None, snp, Failure(Component.TEE)))

        # values matching the LEGACY mapping must fail for a Turin report
        # (they would put bootloader's value on the FMC OID, etc.)
        legacy_values = dict(turin_values)
        legacy_values[az_snp_vtpm.SNP_SPL_OID] = b"\x02\x01\x0f"  # 15 (legacy snp byte)
        legacy_values[az_snp_vtpm.TEE_SPL_OID] = b"\x02\x01\x0b"  # 11 (legacy tee byte)
        legacy_values[az_snp_vtpm.LOADER_SPL_OID] = b"\x02\x01\x0a"  # 10 (legacy loader byte)
        failure = Failure(Component.TEE)
        with patch.object(az_snp_vtpm, "_get_oid_value", side_effect=lambda cert, oid: legacy_values.get(oid)):
            self.assertFalse(az_snp_vtpm.verify_vcek_oids(None, snp, failure))
        self.assertIn(f"{TEE_COMPONENT}.vcek_oid_mismatch", event_ids(failure))

    def test_legacy_oid_check_ignores_fmc(self):
        """FMC is only cross-checked for Turin reports."""
        snp = self.snp_with_cpuid(0x19, 0x11)  # Genoa
        legacy_values = {
            az_snp_vtpm.HW_ID_OID: snp.chip_id,
            az_snp_vtpm.UCODE_SPL_OID: b"\x02\x01\x0e",
            az_snp_vtpm.SNP_SPL_OID: b"\x02\x01\x0f",
            az_snp_vtpm.TEE_SPL_OID: b"\x02\x01\x0b",
            az_snp_vtpm.LOADER_SPL_OID: b"\x02\x01\x0a",
            # no FMC entry at all - must not be required for Genoa
        }
        with patch.object(az_snp_vtpm, "_get_oid_value", side_effect=lambda cert, oid: legacy_values.get(oid)):
            self.assertTrue(az_snp_vtpm.verify_vcek_oids(None, snp, Failure(Component.TEE)))


class MalformedEvidenceTest(unittest.TestCase):
    """Malformed evidence returns a Failure instead of raising.

    The evidence JSON is fully attacker-controlled; every input shape must
    come back as ({}, failure) rather than crash the caller.
    """

    def setUp(self):
        seed_anchor_cache()
        envelope = load_json("evidence-v0-genoa-local.json")
        self.evidence = keylime_evidence(envelope)
        self.nonce = derive_keylime_evidence_nonce(envelope)
        # the baseline fixture must verify before any mutation is applied,
        # so a broken fixture cannot make the negative tests pass vacuously
        self.assert_valid(self.evidence)

    def assert_valid(self, evidence, nonce=None):
        claims, failure = az_snp_vtpm.verify_attestation(evidence, nonce if nonce is not None else self.nonce)
        self.assertEqual(event_ids(failure), [], msg=str(failure.events))
        self.assertTrue(claims, msg=str(failure.events))

    def assert_invalid(self, evidence, code="invalid_input", nonce=None):
        claims, failure = az_snp_vtpm.verify_attestation(evidence, nonce if nonce is not None else self.nonce)
        self.assertEqual(claims, {}, msg=str(failure.events))
        self.assertIn(f"{TEE_COMPONENT}.{code}", event_ids(failure), msg=str(failure.events))

    def valid_v2_evidence(self):
        """The trustee v2 fixture, asserted valid (with its own nonce) first."""
        evidence = load_json("evidence-v2-milan.json")
        self.assert_valid(evidence, nonce=REPORT_DATA_V2)
        return evidence

    def assert_invalid_v2(self, evidence, code="invalid_input"):
        self.assert_invalid(evidence, code=code, nonce=REPORT_DATA_V2)

    @staticmethod
    def synthetic_hcl(claims_bytes, hash_type=az_snp_vtpm.HCL_RUNTIME_DATA_HASH_TYPE_SHA256):
        """Build a minimal HCL container around arbitrary claims bytes."""
        # the header is 32 bytes: six u32 fields plus 12 reserved bytes
        header = struct.pack(
            "<8I",
            az_snp_vtpm.HCL_HEADER_MAGIC,
            2,
            az_snp_vtpm.SNP_REPORT_OFFSET
            + az_snp_vtpm.SNP_REPORT_SIZE
            + az_snp_vtpm.HCL_RUNTIME_DATA_HEADER_SIZE
            + len(claims_bytes),
            2,
            0,
            0,
            0,
            0,
        )
        runtime = struct.pack(
            "<5I",
            az_snp_vtpm.HCL_RUNTIME_DATA_HEADER_SIZE + len(claims_bytes),
            az_snp_vtpm.HCL_RUNTIME_DATA_VERSION,
            2,
            hash_type,
            len(claims_bytes),
        )
        return header + bytes(az_snp_vtpm.SNP_REPORT_SIZE) + runtime + claims_bytes

    def test_non_dict_evidence(self):
        for bad in (None, [], ["evidence"], "evidence", 42, True):
            with self.subTest(bad=bad):
                self.assert_invalid(bad)

    def test_empty_evidence(self):
        self.assert_invalid({})

    def test_v2_wrong_field_types(self):
        evidence = load_json("evidence-v2-milan.json")
        for field in ("hcl_report", "vcek"):
            with self.subTest(field=field):
                for bad in (None, 5, [], {}):
                    broken = json.loads(json.dumps(evidence))
                    broken[field] = bad
                    self.assert_invalid(broken)

    def test_version_type_not_int(self):
        # "version": true must not be accepted as v1 (silent downgrade that
        # would skip the v2 user-data freshness check)
        evidence = load_json("evidence-v2-milan.json")
        evidence["version"] = True
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_evidence(evidence)
        self.assert_invalid(evidence)
        evidence["version"] = 2.0  # float is not an int either
        self.assert_invalid(evidence)

    def test_v0_byte_array_wrong_types(self):
        for bad in (999999999999, -1, "abc", True, None, {"a": 1}):
            with self.subTest(bad=bad):
                broken = json.loads(json.dumps(self.evidence))
                broken["quote"]["message"] = bad
                self.assert_invalid(broken)

    def test_v0_byte_array_bad_element(self):
        for bad in (-1, 256, 2**64, "x", None, 1.5):
            with self.subTest(bad=bad):
                broken = json.loads(json.dumps(self.evidence))
                broken["quote"]["message"] = [255, bad]
                self.assert_invalid(broken)

    def test_v0_vcek_wrong_type(self):
        for bad in (123, None, [], {}):
            with self.subTest(bad=bad):
                broken = json.loads(json.dumps(self.evidence))
                broken["vcek"] = bad
                self.assert_invalid(broken)

    def test_claims_not_an_object(self):
        for claims in (b"[1, 2, 3]", b'"a string"', b"42"):
            with self.subTest(claims=claims):
                with self.assertRaises(ValueError):
                    az_snp_vtpm.parse_hcl_report(self.synthetic_hcl(claims))

    def test_deeply_nested_claims(self):
        # must fail cleanly, not raise RecursionError out of the verifier
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(self.synthetic_hcl(b"[" * 60000))

    def test_claims_keys_not_a_list(self):
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(self.synthetic_hcl(b'{"keys": 5}'))

    def test_claims_keys_wrong_element_type(self):
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(self.synthetic_hcl(b'{"keys": ["HCLAkPub"]}'))

    def test_claims_jwk_missing_fields(self):
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(self.synthetic_hcl(b'{"keys": [{"kid": "HCLAkPub", "kty": "RSA"}]}'))

    def test_claims_jwk_bad_field_types(self):
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(
                self.synthetic_hcl(b'{"keys": [{"kid": "HCLAkPub", "kty": "RSA", "n": 5, "e": "AQAB"}]}')
            )

    def test_claims_user_data_wrong_type(self):
        with self.assertRaises(ValueError):
            az_snp_vtpm.parse_hcl_report(self.synthetic_hcl(b'{"keys": [], "user-data": 5}'))

    def test_bad_init_data_hash_type(self):
        for bad in ("notbytes", 5, [1, 2]):
            with self.subTest(bad=bad):
                claims, failure = az_snp_vtpm.verify_attestation(self.evidence, self.nonce, init_data_hash=bad)
                self.assertEqual(claims, {})
                self.assertIn(f"{TEE_COMPONENT}.invalid_input", event_ids(failure))

    def test_v2_invalid_base64_chars(self):
        """Non-alphabet characters are rejected at parse time, not silently dropped."""
        evidence = self.valid_v2_evidence()
        for field in ("hcl_report", "vcek"):
            with self.subTest(field=field):
                broken = json.loads(json.dumps(evidence))
                broken[field] = "!!!" + broken[field]  # junk chars + otherwise-valid b64
                self.assert_invalid_v2(broken)

    def test_v2_invalid_cc_eventlog_chars(self):
        evidence = self.valid_v2_evidence()
        evidence["cc_eventlog"] = "$$$"
        self.assert_invalid_v2(evidence)

    def test_v2_cc_eventlog_impossible_shape(self):
        # strict std-base64: a 1-char string is not canonical base64
        evidence = self.valid_v2_evidence()
        evidence["cc_eventlog"] = "a"
        self.assert_invalid_v2(evidence)

    @staticmethod
    def tamper_v2_vcek(mutate):
        """Load the v2 fixture's DER vcek, apply mutate(bytearray), re-encode."""
        evidence = load_json("evidence-v2-milan.json")
        der = bytearray(base64.urlsafe_b64decode(evidence["vcek"] + "=="))
        mutate(der)
        evidence["vcek"] = base64.urlsafe_b64encode(bytes(der)).decode("ascii").rstrip("=")
        return evidence

    def test_v2_vcek_bad_version_integer(self):
        """An unsupported certificate version INTEGER fails closed, not with a crash."""

        def mutate(der):
            i = der.find(b"\xa0\x03\x02\x01")  # the version INTEGER wrapper
            der[i + 4] = 0x07  # unsupported version

        self.assert_invalid_v2(self.tamper_v2_vcek(mutate))

    def test_v0_vcek_bad_version_integer(self):
        """Same through the v0 PEM path."""
        evidence = json.loads(json.dumps(self.evidence))
        pem = evidence["vcek"]
        der = bytearray(base64.b64decode("".join(pem.splitlines()[1:-1])))
        i = der.find(b"\xa0\x03\x02\x01")
        der[i + 4] = 0x07
        lines = base64.b64encode(bytes(der)).decode("ascii").splitlines()
        evidence["vcek"] = pem.splitlines()[0] + "\n" + "\n".join(lines) + "\n" + pem.splitlines()[-1] + "\n"
        self.assert_invalid(evidence)

    def test_v2_vcek_unknown_key_algorithm(self):
        """A certificate with an undecodable public key fails closed in phase 8."""

        def mutate(der):
            # the EC public key algorithm OID (1.2.840.10045.2.1) -> unknown arc
            j = der.find(bytes.fromhex("06072a8648ce3d0201"))
            der[j + 3] = 0x99

        evidence = self.tamper_v2_vcek(mutate)
        # end-to-end this fails earlier (phase 6: the tampered tbs breaks the
        # chain signature), so exercise the phase-8 guard directly
        parsed = az_snp_vtpm.parse_evidence(evidence)
        hcl = az_snp_vtpm.parse_hcl_report(parsed.hcl_report)
        snp = az_snp_vtpm.parse_snp_report(hcl.snp_report)
        failure = Failure(Component.TEE)
        self.assertFalse(az_snp_vtpm.verify_snp_report_signature(parsed.vcek, snp, failure))
        self.assertIn(f"{TEE_COMPONENT}.report_signature", event_ids(failure))

    def test_v1_v2_tpm_quote_malformed(self):
        evidence = self.valid_v2_evidence()
        for bad in (None, 5, {}, {"message": "zz", "signature": "00", "pcrs": []}):
            with self.subTest(bad=bad):
                broken = json.loads(json.dumps(evidence))
                broken["tpm_quote"] = bad
                self.assert_invalid_v2(broken)
        broken = json.loads(json.dumps(evidence))
        broken["tpm_quote"]["message"] = "zz"  # non-hex
        self.assert_invalid_v2(broken)
        broken = json.loads(json.dumps(evidence))
        broken["tpm_quote"]["pcrs"] = "notalist"  # non-list
        self.assert_invalid_v2(broken)


class TrustAnchorResolutionTest(unittest.TestCase):
    """Local trust-store resolution and in-memory anchor caching (no network)."""

    def setUp(self):
        az_snp_vtpm.clear_anchor_cache()

    def tearDown(self):
        az_snp_vtpm.clear_anchor_cache()

    def test_resolve_uses_bundled_store_without_network(self):
        # the default resolution must never touch the network
        with patch.object(az_snp_vtpm.requests, "get", side_effect=AssertionError("network access")):
            chains = az_snp_vtpm.resolve_trust_anchors()
        self.assertEqual(set(chains), {"milan", "genoa", "turin"})
        # second resolve: served from the in-memory cache
        with patch.object(az_snp_vtpm.requests, "get", side_effect=AssertionError("network access")):
            self.assertEqual(set(az_snp_vtpm.resolve_trust_anchors()), {"milan", "genoa", "turin"})

    def test_resolve_honors_explicit_path(self):
        # a store with a single generation: only that chain is available
        # and the explicit path replaces the cache
        seed_anchor_cache()  # warm cache must not shadow the explicit path
        with tempfile.TemporaryDirectory() as store:
            with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as src:
                with open(os.path.join(store, "genoa_ask_ark.pem"), "wb") as dst:
                    dst.write(src.read())
            chains = az_snp_vtpm.resolve_trust_anchors(store)
        self.assertEqual(set(chains), {"genoa"})
        self.assertEqual(set(az_snp_vtpm.resolve_trust_anchors()), {"genoa"})

    def test_resolve_honors_config_path(self):
        # the [verifier] amd_anchor_path option points at a custom store
        with tempfile.TemporaryDirectory() as store:
            with open(os.path.join(ANCHOR_STORE, "milan_ask_ark.pem"), "rb") as src:
                with open(os.path.join(store, "milan_ask_ark.pem"), "wb") as dst:
                    dst.write(src.read())
            with patch.object(az_snp_vtpm.config, "get", return_value=store):
                chains = az_snp_vtpm.resolve_trust_anchors()
        self.assertEqual(set(chains), {"milan"})

    def test_resolve_empty_config_uses_bundled_store(self):
        # an empty amd_anchor_path (the default) means the bundled store
        with patch.object(az_snp_vtpm.config, "get", return_value=""):
            self.assertEqual(set(az_snp_vtpm.resolve_trust_anchors()), {"milan", "genoa", "turin"})

    def test_resolve_empty_store_fails(self):
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaises(ValueError):
                az_snp_vtpm.resolve_trust_anchors(empty)

    def test_resolve_returns_snapshot(self):
        # mutating the returned mapping must not affect the process-global cache
        chains = az_snp_vtpm.resolve_trust_anchors()
        chains.pop("milan")
        self.assertIn("milan", az_snp_vtpm.resolve_trust_anchors())

    def test_loader_errors_are_logged(self):
        # a broken store must be visible in the verifier log (WARNING),
        # not only in the failure events of individual attestations
        with self.assertLogs("keylime.az_snp_vtpm", level=logging.WARNING):
            with self.assertRaises(ValueError):
                az_snp_vtpm.resolve_trust_anchors("/nonexistent-anchor-store")
        with tempfile.TemporaryDirectory() as empty:
            with self.assertLogs("keylime.az_snp_vtpm", level=logging.WARNING):
                with self.assertRaises(ValueError):
                    az_snp_vtpm.load_trust_anchors(empty)
        with tempfile.TemporaryDirectory() as store:
            for name in ("a.pem", "b.pem"):
                with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as src:
                    with open(os.path.join(store, name), "wb") as dst:
                        dst.write(src.read())
            with self.assertLogs("keylime.az_snp_vtpm", level=logging.WARNING):
                with self.assertRaises(ValueError):
                    az_snp_vtpm.load_trust_anchors(store)

    def test_load_duplicate_generation_raises(self):
        # two files claiming the same generation are an error, not an overwrite
        with tempfile.TemporaryDirectory() as store:
            for name in ("a.pem", "b.pem"):
                with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as src:
                    with open(os.path.join(store, name), "wb") as dst:
                        dst.write(src.read())
            with self.assertRaises(ValueError):
                az_snp_vtpm.load_trust_anchors(store)

    def test_load_ambiguous_ark_raises(self):
        # two self-signed certificates in one bundle are an ambiguous ARK
        with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as f:
            genoa = x509.load_pem_x509_certificates(f.read())
        with open(os.path.join(ANCHOR_STORE, "turin_ask_ark.pem"), "rb") as f:
            turin = x509.load_pem_x509_certificates(f.read())
        both_arks = b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in (genoa[0], genoa[1], turin[1]))
        with tempfile.TemporaryDirectory() as store:
            with open(os.path.join(store, "mixed.pem"), "wb") as f:
                f.write(both_arks)
            with self.assertRaises(ValueError):
                az_snp_vtpm.load_trust_anchors(store)


class VerifyAnchorsParameterTest(unittest.TestCase):
    """The anchors= parameter of verify_attestation (no network)."""

    def setUp(self):
        az_snp_vtpm.clear_anchor_cache()

    def tearDown(self):
        az_snp_vtpm.clear_anchor_cache()

    def test_anchors_parameter_supplies_the_trust_store(self):
        # cold cache + caller-supplied anchors: no store resolution at all
        evidence = load_json("evidence-v2-milan.json")
        with patch.object(az_snp_vtpm, "resolve_trust_anchors", side_effect=AssertionError("must not resolve")):
            _claims, failure = az_snp_vtpm.verify_attestation(
                evidence, REPORT_DATA_V2, anchors={"milan": TRUST_ANCHORS["milan"]}
            )
        self.assertEqual(event_ids(failure), [], msg=str(failure.events))

    def test_anchors_parameter_missing_generation_fails_closed(self):
        evidence = load_json("evidence-v2-milan.json")
        with patch.object(az_snp_vtpm, "resolve_trust_anchors", side_effect=AssertionError("must not resolve")):
            claims, failure = az_snp_vtpm.verify_attestation(
                evidence, REPORT_DATA_V2, anchors={"genoa": TRUST_ANCHORS["genoa"]}
            )
        self.assertEqual(claims, {})
        self.assertIn(f"{TEE_COMPONENT}.vcek_chain", event_ids(failure))


class KdsFetchTest(unittest.TestCase):
    """fetch_kds_chain() as a provisioning utility (no network in tests)."""

    def test_fetch_kds_chain(self):
        with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as f:
            body = f.read()
        response = unittest.mock.Mock(status_code=200, content=body)
        with patch.object(az_snp_vtpm.requests, "get", return_value=response) as mock_get:
            ask, ark = az_snp_vtpm.fetch_kds_chain("genoa")
        mock_get.assert_called_once_with(
            "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain",
            timeout=az_snp_vtpm.KDS_FETCH_TIMEOUT,
            allow_redirects=False,
        )
        self.assertEqual(az_snp_vtpm._cert_common_name(ask), "SEV-Genoa")  # pylint: disable=protected-access
        self.assertEqual(az_snp_vtpm._cert_common_name(ark), "ARK-Genoa")  # pylint: disable=protected-access

    def test_fetch_kds_chain_bad_status(self):
        response = unittest.mock.Mock(status_code=503, content=b"")
        with patch.object(az_snp_vtpm.requests, "get", return_value=response):
            with self.assertRaises(ValueError):
                az_snp_vtpm.fetch_kds_chain("genoa")

    def test_fetch_kds_chain_garbage_body(self):
        response = unittest.mock.Mock(status_code=200, content=b"not a pem")
        with patch.object(az_snp_vtpm.requests, "get", return_value=response):
            with self.assertRaises(ValueError):
                az_snp_vtpm.fetch_kds_chain("genoa")

    def test_fetch_kds_chain_invalid_pair(self):
        # ASK and ARK from different generations do not sign each other
        with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as f:
            genoa = x509.load_pem_x509_certificates(f.read())
        with open(os.path.join(ANCHOR_STORE, "turin_ask_ark.pem"), "rb") as f:
            turin = x509.load_pem_x509_certificates(f.read())
        mixed = b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in (genoa[0], turin[1]))
        response = unittest.mock.Mock(status_code=200, content=mixed)
        with patch.object(az_snp_vtpm.requests, "get", return_value=response):
            with self.assertRaises(ValueError):
                az_snp_vtpm.fetch_kds_chain("genoa")

    def test_fetch_kds_chain_bad_version_integer(self):
        """A bundle with an unsupported certificate version fails as ValueError, not InvalidVersion."""
        with open(os.path.join(ANCHOR_STORE, "genoa_ask_ark.pem"), "rb") as f:
            genoa = x509.load_pem_x509_certificates(f.read())
        der = bytearray(genoa[0].public_bytes(serialization.Encoding.DER))
        i = der.find(b"\xa0\x03\x02\x01")
        der[i + 4] = 0x07
        # re-wrap the tampered DER in a minimal PEM bundle
        pem = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(bytes(der)) + b"\n-----END CERTIFICATE-----\n"
        response = unittest.mock.Mock(status_code=200, content=pem)
        with patch.object(az_snp_vtpm.requests, "get", return_value=response):
            with self.assertRaises(ValueError):
                az_snp_vtpm.fetch_kds_chain("genoa")


if __name__ == "__main__":
    unittest.main()
