import codecs
import copy
import hashlib
import os
import unittest
from typing import List, cast

from keylime import json
from keylime.agentstates import AgentAttestState
from keylime.ima import file_signatures, ima
from keylime.ima.types import RuntimePolicyType

# BEGIN TEST DATA

RUNTIME_POLICY_TEST: RuntimePolicyType = {
    "meta": {
        "version": 1,
    },
    "digests": {
        "boot_aggregate": ["e4cb9f5709c88376b5fc3743cd88e76b9aae8f3d992d845678de5215edb31216"],
        "/lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko": [
            "f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e"
        ],
        "/lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko": [
            "cd026b58efdf66658685430ff526490d54a430a3f0066a35ac26a8acab66c55d"
        ],
        "/usr/bin/dd": ["d33d5d13792292e202dbf69a6f1b07bc8a02f01424db8489ba7bb7d43c0290ef"],
        "/usr/bin/zmore": ["b8ae0b8dd04a5935cd8165aa2260cd11b658bd71629bdb52256a675a1f73907b"],
        "/usr/bin/zless": ["233ad3a8e77c63a7d9a56063ec2cad1eafa58850"],
    },
    "excludes": [],
    "keyrings": {
        ".ima": ["a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a"],
    },
    "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1", "dm_policy": None},
    "ima-buf": {},
    "verification-keys": "",
}

# Allowlist with different hashes
RUNTIME_POLICY_WRONG: RuntimePolicyType = {
    "meta": {
        "version": 1,
    },
    "digests": {
        "/usr/bin/dd": ["bad05d13792292e202dbf69a6f1b07bc8a02f01424db8489ba7bb7d43c0290ef"],
        "/usr/bin/zmore": ["bad00b8dd04a5935cd8165aa2260cd11b658bd71629bdb52256a675a1f73907b"],
    },
    "excludes": [],
    "keyrings": {},
    "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1", "dm_policy": None},
    "ima-buf": {},
    "verification-keys": "",
}

EXCLUDES = [
    "boot_aggregate",
    "/lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko",
    "/lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko",
    "/usr/bin/dd",
    "/usr/bin/zmore",
    "/usr/bin/zless",
]

RUNTIME_POLICY_WITH_EXCLUDES = copy.deepcopy(RUNTIME_POLICY_TEST)
RUNTIME_POLICY_WITH_EXCLUDES["excludes"] = EXCLUDES

RUNTIME_POLICY_WRONG_WITH_EXCLUDES = copy.deepcopy(RUNTIME_POLICY_WRONG)
RUNTIME_POLICY_WRONG_WITH_EXCLUDES["excludes"] = EXCLUDES

MEASUREMENTS: str = (
    "10 0c8a706a75a5689c1e168f0a573a3cbec33061b5 ima-sig sha256:e4cb9f5709c88376b5fc3743cd88e76b9aae8f3d992d845678de5215edb31216 boot_aggregate \n"
    "10 5426cf3031a43f5bfca183d79950698a95a728f6 ima-sig sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e /lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko \n"
    "10 f8a7b32dba2cb3a5437786d7f9d5caee8db3115b ima-sig sha256:cd026b58efdf66658685430ff526490d54a430a3f0066a35ac26a8acab66c55d /lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko \n"
)

# 1st signature: RSA
# 2nd signature: EC
SIGNATURES: str = (
    "10 1e70a3e1af66f42826ad63b761b4cb9c4df195e1 ima-sig sha256:d33d5d13792292e202dbf69a6f1b07bc8a02f01424db8489ba7bb7d43c0290ef /usr/bin/dd 030204f3452d2301009dd340c852f37e35748363586939d4199b6684be27e7c1236ca1528f708372ed9cd52a0d991f66448790f5616ed5bd7f9bbd22193b1e3e54f6bf29a1497945a34d1b418b24f4cbeaef897bf3cebca27065ebb8761b46bc2662fe76f141245b9186a5ac8493c7f4976cf0d6dfc085c3e503e3f771bc3ccb121230db76fd8aba4f45f060ad64ab3afd99b4e52824b9eba12e93e46f9dcb2fa01d9cef89f298a0da02a82a4fb56924afd3e3c277a1302d99f770d488449df2d43eb5b174a0a528827e6877b965c2f0b7c89cf1aa26a7417a892df4c2294e2872d62748b72ea04ecb0689b5d792e615a9bf9d56f6e0f298560bf9441df0a22729c5f23389f028c25f\n"
    "10 5d4d5141ccd5066d50dc3f21d79ba02fedc24256 ima-sig sha256:b8ae0b8dd04a5935cd8165aa2260cd11b658bd71629bdb52256a675a1f73907b /usr/bin/zmore 030204531f402500483046022100fe24678d21083ead47660e1a2d553a592d777c478d1b0466de6ed484b54956b3022100cad3adb37f277bbb03544d6107751b4cd4f2289d8353fa36257400a99334d5c3\n"
)

COMBINED: str = MEASUREMENTS + SIGNATURES

# Malformatted signature with bad size indicator
BAD_SIGNATURES: str = "10 5d4d5141ccd5066d50dc3f21d79ba02fedc24256 ima-sig sha256:b8ae0b8dd04a5935cd8165aa2260cd11b658bd71629bdb52256a675a1f73907b /usr/bin/zmore 030204531f402548003046022100fe24678d21083ead47660e1a2d553a592d777c478d1b0466de6ed484b54956b3022100cad3adb37f277bbb03544d6107751b4cd4f2289d8353fa36257400a99334d5c3\n"

KEYRINGS: str = "10 978351440c6c8a17568f0c366b9ede28efd14f8c ima-buf sha256:a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a .ima 308201d130820178a003020102020101300906072a8648ce3d0401301b3119301706035504030c1054657374696e672d45434453412d4341301e170d3231303631313133353831365a170d3232303631313133353831365a3021311f301d06035504030c1665636473612d63612d7369676e65642d65632d6b65793059301306072a8648ce3d020106082a8648ce3d030107034200044ce55be36765b59de2767f6d6721be8bea8e3db4ccc25ab76c30f5d1c11752ae1699cc39d31b378f69fecbe65ce1eb09e075f840fe4c052bafb9039742b76202a381a73081a430090603551d1304023000301d0603551d0e04160414b6fb3c083d19695be441c5f59afb95742cb6058c30560603551d23044f304d80140a51da379e45bd7ac623c3f765b53e1e2dde5195a11fa41d301b3119301706035504030c1054657374696e672d45434453412d434182142bb351b0d645e4d8594316ac3c96fc6d9c83791530130603551d25040c300a06082b06010505070302300b0603551d0f040403020780300906072a8648ce3d04010348003045022033d47b623c9feefab7d6e68b001ac6463433f99b61ce7b951a32da065a5d17af022100f3d73e38070053aec63a941ed36ae0dcfa25ed9cd538c459732a7e782132a4ca"

RUNTIME_POLICY_WITH_VERIFICATION_KEYS: RuntimePolicyType = {
    "meta": {"version": 1, "generator": 3, "timestamp": "2024-08-28 15:13:11.952478"},
    "release": 0,
    "digests": {"boot_aggregate": ["0000000000000000000000000000000000000000000000000000000000000000"]},
    "excludes": [],
    "keyrings": {},
    "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1", "dm_policy": None},
    "ima-buf": {},
    "verification-keys": '{"pubkeys": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1cD7bW5tX5qIVgWskS5tzY+XpqWzcW6HFq5npj8dHFIWsAJJCUdoSU631hkyY8HP/RfXDPq/J4IeKvx35EVXj49t1Z1FTJBgUlEbkKvqm0rY6jo7PnJ6BsDRrauXtiEXVKNXcWXDk8ES+9v9Cz26BJYAr+5Xgm2aEyAbj8GhicxUZfsjDm8eJ7ZnQKuhF7jejG5dYAYxnBVu99bQJHI5Fsu3dAjGbys9v7ToNbonS+1bJXdHyEE0swhxBOPvvV6vx5CzRNw1Sou3rT19T4j8wpsFOyYXVcbbRVBAmBE2Qy2UHvojFqaJN/A9lztllyER1S5heGG6CxK3GoR6pkOXAQIDAQAB", "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnNH3Y/xOTwRRd8D6hpodRLnVx71qDTLvJHouno7nU7JSzcXWN1PxK+HQEh1V7sMdwBER4KFKE635JTv6C+BRBg=="], "keyids": [4081397027, 1394556965]}',
}

IMA_KEYRING_STRING: str = '{"pubkeys": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1cD7bW5tX5qIVgWskS5tzY+XpqWzcW6HFq5npj8dHFIWsAJJCUdoSU631hkyY8HP/RfXDPq/J4IeKvx35EVXj49t1Z1FTJBgUlEbkKvqm0rY6jo7PnJ6BsDRrauXtiEXVKNXcWXDk8ES+9v9Cz26BJYAr+5Xgm2aEyAbj8GhicxUZfsjDm8eJ7ZnQKuhF7jejG5dYAYxnBVu99bQJHI5Fsu3dAjGbys9v7ToNbonS+1bJXdHyEE0swhxBOPvvV6vx5CzRNw1Sou3rT19T4j8wpsFOyYXVcbbRVBAmBE2Qy2UHvojFqaJN/A9lztllyER1S5heGG6CxK3GoR6pkOXAQIDAQAB", "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnNH3Y/xOTwRRd8D6hpodRLnVx71qDTLvJHouno7nU7JSzcXWN1PxK+HQEh1V7sMdwBER4KFKE635JTv6C+BRBg=="], "keyids": [4081397027, 1394556965]}'

IMA_BAD_KEYRING_STRING: str = '{"pubkeys": ["MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1cD7bW5tX5qIVgWskS5tzY+XpqWzcW6HFq5npj8dHFIWsAJJCUdoSU631hkyY8HP/RfXDPq/J4IeKvx35EVXj49t1Z1FTJBgUlEbkKvqm0rY6jo7PnJ6BsDRrauXtiEXVKNXcWXDk8ES+9v9Cz26BJYAr+5Xgm2aEyAbj8GhicxUZfsjDm8eJ7ZnQKuhF7jejG5dYAYxnBVu99bQJHI5Fsu3dAjGbys9v7ToNbonS+1bJXdHyEE0swhxBOPvvV6vx5CzRNw1Sou3rT19T4j8wpsFOyYXVcbbRVBAmBE2Qy2UHvojFqaJN/A9lztllyER1S5heGG6CxK3GoR6pkOXAQIDAQAB", "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEnNH3Y/xOTwRRd8D6hpodRLnVx71qDTLvJHouno7nU7JSzcXWN1PxK+HQEh1V7sMdwBER4KFKE635JTv6C+BRBg=="]}'

# END TEST DATA


class TestIMAVerification(unittest.TestCase):
    """Test the IMA measurement list verification"""

    def test_measurment_verification(self):
        """Test IMA measurement list verification"""
        _measurements = MEASUREMENTS.splitlines()
        measurements = cast(List[str], _measurements)

        _, failure = ima.process_measurement_list(AgentAttestState("1"), measurements)
        self.assertTrue(not failure, "Validation should always work when no allowlist and no keyring is specified")

        # test with list with JSON
        _, failure = ima.process_measurement_list(AgentAttestState("1"), measurements, RUNTIME_POLICY_TEST)
        self.assertTrue(not failure)

        # No files are in the allowlist -> this should fail
        _, failure = ima.process_measurement_list(AgentAttestState("1"), measurements, ima.EMPTY_RUNTIME_POLICY)
        self.assertTrue(failure)

    def test_signature_verification(self):
        """Test the signature verification"""
        curdir = os.path.dirname(os.path.abspath(__file__))
        keydir = os.path.join(curdir, "data", "ima_keys")

        _signatures = SIGNATURES.split("\n")
        signatures = cast(List[str], _signatures)

        # empty keyring
        keyrings = file_signatures.ImaKeyrings()
        _, failure = ima.process_measurement_list(AgentAttestState("1"), signatures, ima_keyrings=keyrings)
        self.assertTrue(failure)

        tenant_keyring = file_signatures.ImaKeyring()
        keyrings.set_tenant_keyring(tenant_keyring)

        # add key for 1st entry; 1st entry must be verifiable
        rsakeyfile = os.path.join(keydir, "rsa2048pub.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(rsakeyfile)
        assert pubkey is not None
        tenant_keyring.add_pubkey(pubkey, keyidv2)
        _, failure = ima.process_measurement_list(AgentAttestState("1"), signatures[0:1], ima_keyrings=keyrings)
        self.assertTrue(not failure)
        _, failure = ima.process_measurement_list(AgentAttestState("1"), signatures[1:2], ima_keyrings=keyrings)
        self.assertTrue(failure)

        # add key for 2nd entry; 1st & 2nd entries must be verifiable
        eckeyfile = os.path.join(keydir, "secp256k1.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(eckeyfile)
        assert pubkey is not None
        tenant_keyring.add_pubkey(pubkey, keyidv2)
        _, failure = ima.process_measurement_list(AgentAttestState("1"), signatures[0:2], ima_keyrings=keyrings)
        self.assertTrue(not failure)

    def test_ima_buf_verification(self):
        """The verification of ima-buf entries supporting keys loaded onto keyrings"""
        ima_keyrings = file_signatures.ImaKeyrings()

        self.assertTrue(
            ima.process_measurement_list(
                AgentAttestState("1"), KEYRINGS.splitlines(), RUNTIME_POLICY_TEST, ima_keyrings=ima_keyrings
            )
            is not None
        )

    def test_iterative_attestation(self):
        """Test that the resulting pcr value is as expected by subsequently feeding a measurement list.
        The AgentAtestState() will maintain the state of PCR 10.
        """

        pcrval = None
        lines = MEASUREMENTS.splitlines()
        agentAttestState = AgentAttestState("1")
        running_hash = agentAttestState.get_pcr_state(10)
        assert running_hash is not None
        for line in lines:
            parts = line.split(" ")
            template_hash = bytes.fromhex(parts[1])
            running_hash = hashlib.sha1(running_hash + template_hash).digest()
            pcrval = codecs.encode(running_hash, "hex").decode("utf-8")
            ima_hash, _ = ima.process_measurement_list(agentAttestState, [line], pcrval=pcrval)
            self.assertTrue(ima_hash == pcrval)

        # Feed empty iterative measurement list simulating 'no new measurement list entries' on attested system
        ima_hash, _ = ima.process_measurement_list(agentAttestState, [], pcrval=pcrval)
        self.assertTrue(ima_hash == pcrval)

    def test_mixed_verfication(self):
        """Test verification using allowlist and keys"""

        ima_keyrings = file_signatures.ImaKeyrings()
        empty_keyring = file_signatures.ImaKeyring()

        _combined = COMBINED.splitlines()
        combined = cast(List[str], _combined)

        # every entry is covered by the allowlist and there's no keyring -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState("1"), combined, RUNTIME_POLICY_TEST)
        self.assertTrue(not failure)

        curdir = os.path.dirname(os.path.abspath(__file__))
        keydir = os.path.join(curdir, "data", "ima_keys")
        tenant_keyring = file_signatures.ImaKeyring()

        rsakeyfile = os.path.join(keydir, "rsa2048pub.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(rsakeyfile)
        assert pubkey is not None
        tenant_keyring.add_pubkey(pubkey, keyidv2)

        eckeyfile = os.path.join(keydir, "secp256k1.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(eckeyfile)
        assert pubkey is not None
        tenant_keyring.add_pubkey(pubkey, keyidv2)

        ima_keyrings.set_tenant_keyring(tenant_keyring)

        # entries are not covered by a exclude list -> this should fail
        _, failure = ima.process_measurement_list(AgentAttestState("1"), combined, ima_keyrings=ima_keyrings)
        self.assertTrue(failure)

        # all entries are either covered by allow list or by signature verification -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), combined, RUNTIME_POLICY_TEST, ima_keyrings=ima_keyrings
        )
        self.assertTrue(not failure)

        _signatures = SIGNATURES.splitlines()
        signatures = cast(List[str], _signatures)

        # the signature is valid but the hash in the allowlist is wrong -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), signatures, RUNTIME_POLICY_WRONG, ima_keyrings=ima_keyrings
        )
        self.assertTrue(not failure)

        # the signature is valid and the file is not in the allowlist -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), signatures, ima.EMPTY_RUNTIME_POLICY, ima_keyrings=ima_keyrings
        )
        self.assertTrue(not failure)

        # the signature is invalid but the correct hash is in the allowlist -> this should pass
        ima_keyrings.set_tenant_keyring(empty_keyring)
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), signatures, RUNTIME_POLICY_TEST, ima_keyrings=ima_keyrings
        )
        self.assertTrue(not failure)

        _measurements = MEASUREMENTS.splitlines()
        measurements = cast(List[str], _measurements)

        # the file has no signature but the hash is correct -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState("1"), measurements, RUNTIME_POLICY_TEST)
        self.assertTrue(not failure)

        # All files are in the exclude list but hashes are invalid -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), measurements, RUNTIME_POLICY_WRONG_WITH_EXCLUDES
        )
        self.assertTrue(not failure)

        # All files are in the exclude list and their signatures are invalid -> this should pass
        ima_keyrings.set_tenant_keyring(tenant_keyring)
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), signatures, RUNTIME_POLICY_WITH_EXCLUDES, ima_keyrings=ima_keyrings
        )
        self.assertTrue(not failure)

        # All files are in the exclude list but hashes or signatures are invalid -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"),
            measurements,
            RUNTIME_POLICY_WRONG_WITH_EXCLUDES,
            ima_keyrings=ima_keyrings,
        )
        self.assertTrue(not failure)

        _bad_signatures = BAD_SIGNATURES.splitlines()
        bad_signatures = cast(List[str], _bad_signatures)

        # The signature is malformatted and the file is in the exclude list -> this must not pass
        ima_keyrings.set_tenant_keyring(empty_keyring)
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), bad_signatures, RUNTIME_POLICY_WITH_EXCLUDES, ima_keyrings=ima_keyrings
        )
        self.assertTrue(failure)

        # The signature is malformatted and the file is in the accept list -> this must not pass
        ima_keyrings.set_tenant_keyring(empty_keyring)
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), bad_signatures, RUNTIME_POLICY_TEST, ima_keyrings=ima_keyrings
        )
        self.assertTrue(failure)

    def test_read_allowlist(self):
        """Test reading and processing of the IMA allow-list"""

        curdir = os.path.dirname(os.path.abspath(__file__))
        allowlist_file = os.path.join(curdir, "data", "runtime-policy-test.json")
        allowlist_file_signed = os.path.join(curdir, "data", "runtime-policy-test-signed.json")
        allowlist_file_signed_bad = os.path.join(curdir, "data", "runtime-policy-test-signed-bad.json")
        allowlist_dsse_key = os.path.join(curdir, "data", "runtime-policy-pubkey.pub")
        allowlist_checksum = "64608ceb82d6d6459e8ac5ffd19865d670d1fe99417e10f20446de5d125bc4ab"
        allowlist_signed_checksum = "ed42c2beda1207061187a5e03b1faaf4cb3e2ff57121cb823ac92b536800e027"
        allowlist_bad_checksum = "4c143670836f96535d9e617359b4d87c59e89e633e2773b4d7feae97f561b3dc"

        # simple read, no fancy verification
        runtime_policy, _ = ima.read_runtime_policy(allowlist_file)
        runtime_policy = json.loads(runtime_policy)
        self.assertIsNotNone(runtime_policy, "Runtime policy data is present")
        self.assertIsNotNone(runtime_policy["meta"], "Runtime policy metadata is present")
        self.assertEqual(runtime_policy["meta"]["version"], 1, "Runtime policy metadata version is correct")
        self.assertEqual(
            runtime_policy["meta"]["generator"],
            ima.RUNTIME_POLICY_GENERATOR.CompatibleAllowList,
            "Runtime policy metadata generator is correct",
        )
        self.assertIsNotNone(runtime_policy["digests"], "Runtime policy digests are present")
        self.assertEqual(len(runtime_policy["digests"]), 21, "Runtime policy hashes are correct length")
        self.assertEqual(
            runtime_policy["digests"]["/boot/grub2/i386-pc/testload.mod"][0],
            "68e1d012e3f193dcde955e6ffbbc80e22b0f8778",
            "Runtime policy sample hash is correct",
        )
        self.assertIsNotNone(runtime_policy["keyrings"], "Runtime policy keyrings are present")
        self.assertEqual(len(runtime_policy["keyrings"]), 1, "Runtime policy keyrings are correct length")
        self.assertEqual(
            runtime_policy["keyrings"][".ima"][0],
            "a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a",
            "Runtime policy sample keyring is correct",
        )

        # validate checksum
        runtime_policy, _ = ima.read_runtime_policy(allowlist_file, allowlist_checksum)
        runtime_policy = json.loads(runtime_policy)
        self.assertIsNotNone(runtime_policy, "Runtime policy data is present")
        self.assertIsNotNone(runtime_policy["digests"], "Runtime policy hashes are present")
        self.assertEqual(len(runtime_policy["digests"]), 21, "Runtime policy hashes are correct length")
        self.assertEqual(
            runtime_policy["digests"]["/boot/grub2/i386-pc/testload.mod"][0],
            "68e1d012e3f193dcde955e6ffbbc80e22b0f8778",
            "Runtime policy sample hash is correct",
        )

        # test with a bad checksum
        with self.assertRaises(Exception) as bad_checksum_context:
            ima.read_runtime_policy(allowlist_file, allowlist_bad_checksum)
        self.assertIn("Checksum of runtime policy does not match", str(bad_checksum_context.exception))

        # validate DSSE signature (tenant side)
        runtime_policy_envelope_raw, runtime_policy_key = ima.read_runtime_policy(
            allowlist_file_signed, None, allowlist_dsse_key
        )
        runtime_policy_envelope = json.loads(runtime_policy_envelope_raw)
        self.assertIsNotNone(runtime_policy_envelope, "Runtime policy envelope data is present")
        self.assertIsNotNone(runtime_policy_key, "Runtime policy signing key is present")
        self.assertIsNotNone(runtime_policy_envelope["payload"], "DSSE payload is present")
        self.assertIsNotNone(runtime_policy_envelope["payloadType"], "DSSE payload type is present")
        self.assertEqual(
            runtime_policy_envelope["payloadType"],
            "application/vnd.keylime+json",
            "DSSE payload is present",
        )

        # deserialize DSSE payload
        runtime_policy = ima.deserialize_runtime_policy(runtime_policy_envelope_raw.decode())
        self.assertIsNotNone(runtime_policy["digests"], "Runtime policy hashes are present")
        self.assertEqual(len(runtime_policy["digests"]), 21, "Runtime policy hashes are correct length")
        self.assertEqual(
            runtime_policy["digests"]["/boot/grub2/i386-pc/testload.mod"][0],
            "68e1d012e3f193dcde955e6ffbbc80e22b0f8778",
            "Runtime policy sample hash is correct",
        )

        # test with a bad DSSE signature (tenant-side)
        with self.assertRaises(Exception) as bad_sig_context:
            ima.read_runtime_policy(allowlist_file_signed_bad, None, allowlist_dsse_key)
        self.assertIn("Runtime policy failed DSSE signature verification!", str(bad_sig_context.exception))

        # validate DSSE signature (verifier side)
        runtime_policy, runtime_policy_key = ima.read_runtime_policy(allowlist_file_signed, None, allowlist_dsse_key)
        ima.verify_runtime_policy(runtime_policy, runtime_policy_key)

        # test with a bad sig (verifier-side)

        with open(allowlist_file_signed_bad, "rb") as bad_sig_f:
            runtime_policy_bad = bad_sig_f.read()
        with self.assertRaises(ima.ImaValidationError) as bad_sig_context:
            ima.verify_runtime_policy(runtime_policy_bad, runtime_policy_key)
        self.assertIn("Runtime policy failed DSSE signature verification!", bad_sig_context.exception.message)
        self.assertEqual(bad_sig_context.exception.code, 401)

        # validate everything together
        runtime_policy_envelope_raw, runtime_policy_key = ima.read_runtime_policy(
            allowlist_file_signed, allowlist_signed_checksum, allowlist_dsse_key
        )
        runtime_policy_envelope = json.loads(runtime_policy_envelope_raw)
        self.assertIsNotNone(runtime_policy_envelope, "Runtime policy envelope data is present")
        self.assertIsNotNone(runtime_policy_key, "Runtime policy signing key is present")
        self.assertIsNotNone(runtime_policy_envelope["payload"], "DSSE payload is present")
        self.assertIsNotNone(runtime_policy_envelope["payloadType"], "DSSE payload type is present")
        self.assertEqual(
            runtime_policy_envelope["payloadType"],
            "application/vnd.keylime+json",
            "DSSE payload is present",
        )

        # deserialize DSSE payload
        runtime_policy = ima.deserialize_runtime_policy(runtime_policy_envelope_raw.decode())
        self.assertIsNotNone(runtime_policy["digests"], "Runtime policy hashes are present")
        self.assertEqual(len(runtime_policy["digests"]), 21, "Runtime policy hashes are correct length")
        self.assertEqual(
            runtime_policy["digests"]["/boot/grub2/i386-pc/testload.mod"][0],
            "68e1d012e3f193dcde955e6ffbbc80e22b0f8778",
            "Runtime policy sample hash is correct",
        )

    def test_from_string_validates_json_schema(self) -> None:
        """Test if from_string validates JSON schema"""

        keyring = file_signatures.ImaKeyring.from_string(IMA_KEYRING_STRING)
        self.assertIsNotNone(keyring)
        if keyring:
            self.assertEqual(keyring.to_string(), IMA_KEYRING_STRING)

        should_be_none = None
        with self.assertLogs("keylime.file_signatures", level="ERROR") as context:
            should_be_none = file_signatures.ImaKeyring.from_string(IMA_BAD_KEYRING_STRING)

        self.assertTrue("JSON from string is not a valid IMA Keyring" in str(context.output))
        self.assertIsNone(should_be_none)
