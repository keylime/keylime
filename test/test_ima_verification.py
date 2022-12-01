"""
SPDX-License-Identifier: Apache-2.0
Copyright 2020 IBM Corporation
"""

import base64
import codecs
import hashlib
import os
import unittest

from keylime import json
from keylime.agentstates import AgentAttestState
from keylime.ima import file_signatures, ima

# BEGIN TEST DATA

ALLOWLIST = {
    "meta": {
        "version": 6,
    },
    "hashes": {
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
    "keyrings": {
        ".ima": ["a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a"],
    },
    "ima": {"dm_policy": None},
}

ALLOWLIST_EMPTY = {
    "meta": {
        "version": 1,
    },
    "hashes": {},
}

# Allowlist with different hashes
ALLOWLIST_WRONG = {
    "meta": {
        "version": 1,
    },
    "hashes": {
        "/usr/bin/dd": ["bad05d13792292e202dbf69a6f1b07bc8a02f01424db8489ba7bb7d43c0290ef"],
        "/usr/bin/zmore": ["bad00b8dd04a5935cd8165aa2260cd11b658bd71629bdb52256a675a1f73907b"],
    },
}

EXCLUDELIST = [
    "boot_aggregate",
    "/lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko",
    "/lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko",
    "/usr/bin/dd",
    "/usr/bin/zmore",
    "/usr/bin/zless",
]

MEASUREMENTS = (
    "10 0c8a706a75a5689c1e168f0a573a3cbec33061b5 ima-sig sha256:e4cb9f5709c88376b5fc3743cd88e76b9aae8f3d992d845678de5215edb31216 boot_aggregate \n"
    "10 5426cf3031a43f5bfca183d79950698a95a728f6 ima-sig sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e /lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko \n"
    "10 f8a7b32dba2cb3a5437786d7f9d5caee8db3115b ima-sig sha256:cd026b58efdf66658685430ff526490d54a430a3f0066a35ac26a8acab66c55d /lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko \n"
)

# 1st signature: RSA
# 2nd signature: EC
SIGNATURES = (
    "10 1e70a3e1af66f42826ad63b761b4cb9c4df195e1 ima-sig sha256:d33d5d13792292e202dbf69a6f1b07bc8a02f01424db8489ba7bb7d43c0290ef /usr/bin/dd 030204f3452d2301009dd340c852f37e35748363586939d4199b6684be27e7c1236ca1528f708372ed9cd52a0d991f66448790f5616ed5bd7f9bbd22193b1e3e54f6bf29a1497945a34d1b418b24f4cbeaef897bf3cebca27065ebb8761b46bc2662fe76f141245b9186a5ac8493c7f4976cf0d6dfc085c3e503e3f771bc3ccb121230db76fd8aba4f45f060ad64ab3afd99b4e52824b9eba12e93e46f9dcb2fa01d9cef89f298a0da02a82a4fb56924afd3e3c277a1302d99f770d488449df2d43eb5b174a0a528827e6877b965c2f0b7c89cf1aa26a7417a892df4c2294e2872d62748b72ea04ecb0689b5d792e615a9bf9d56f6e0f298560bf9441df0a22729c5f23389f028c25f\n"
    "10 5d4d5141ccd5066d50dc3f21d79ba02fedc24256 ima-sig sha256:b8ae0b8dd04a5935cd8165aa2260cd11b658bd71629bdb52256a675a1f73907b /usr/bin/zmore 030204531f402500483046022100fe24678d21083ead47660e1a2d553a592d777c478d1b0466de6ed484b54956b3022100cad3adb37f277bbb03544d6107751b4cd4f2289d8353fa36257400a99334d5c3\n"
)

COMBINED = MEASUREMENTS + SIGNATURES

KEYRINGS = "10 978351440c6c8a17568f0c366b9ede28efd14f8c ima-buf sha256:a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a .ima 308201d130820178a003020102020101300906072a8648ce3d0401301b3119301706035504030c1054657374696e672d45434453412d4341301e170d3231303631313133353831365a170d3232303631313133353831365a3021311f301d06035504030c1665636473612d63612d7369676e65642d65632d6b65793059301306072a8648ce3d020106082a8648ce3d030107034200044ce55be36765b59de2767f6d6721be8bea8e3db4ccc25ab76c30f5d1c11752ae1699cc39d31b378f69fecbe65ce1eb09e075f840fe4c052bafb9039742b76202a381a73081a430090603551d1304023000301d0603551d0e04160414b6fb3c083d19695be441c5f59afb95742cb6058c30560603551d23044f304d80140a51da379e45bd7ac623c3f765b53e1e2dde5195a11fa41d301b3119301706035504030c1054657374696e672d45434453412d434182142bb351b0d645e4d8594316ac3c96fc6d9c83791530130603551d25040c300a06082b06010505070302300b0603551d0f040403020780300906072a8648ce3d04010348003045022033d47b623c9feefab7d6e68b001ac6463433f99b61ce7b951a32da065a5d17af022100f3d73e38070053aec63a941ed36ae0dcfa25ed9cd538c459732a7e782132a4ca"

# END TEST DATA


class TestIMAVerification(unittest.TestCase):
    """Test the IMA measurement list verification"""

    def test_measurment_verification(self):
        """Test IMA measurement list verification"""
        lines = MEASUREMENTS.splitlines()
        lists_map = ima.process_ima_policy(ALLOWLIST, [])
        lists_map_empty = ima.process_ima_policy(ALLOWLIST_EMPTY, [])

        _, failure = ima.process_measurement_list(AgentAttestState("1"), lines)
        self.assertTrue(not failure, "Validation should always work when no allowlist and no keyring is specified")

        _, failure = ima.process_measurement_list(AgentAttestState("1"), lines, lists_map)
        self.assertTrue(not failure)
        # test with list with JSON
        _, failure = ima.process_measurement_list(AgentAttestState("1"), lines, json.dumps(lists_map))
        self.assertTrue(not failure)

        # No files are in the allowlist -> this should fail
        _, failure = ima.process_measurement_list(AgentAttestState("1"), lines, lists_map_empty)
        self.assertTrue(failure)

    def test_signature_verification(self):
        """Test the signature verification"""
        curdir = os.path.dirname(os.path.abspath(__file__))
        keydir = os.path.join(curdir, "data", "ima_keys")

        lines = SIGNATURES.split("\n")

        # empty keyring
        keyrings = file_signatures.ImaKeyrings()
        _, failure = ima.process_measurement_list(AgentAttestState("1"), lines, ima_keyrings=keyrings)
        self.assertTrue(failure)

        tenant_keyring = file_signatures.ImaKeyring()
        keyrings.set_tenant_keyring(tenant_keyring)

        # add key for 1st entry; 1st entry must be verifiable
        rsakeyfile = os.path.join(keydir, "rsa2048pub.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(rsakeyfile)
        assert pubkey is not None
        tenant_keyring.add_pubkey(pubkey, keyidv2)
        _, failure = ima.process_measurement_list(AgentAttestState("1"), lines[0:1], ima_keyrings=keyrings)
        self.assertTrue(not failure)
        _, failure = ima.process_measurement_list(AgentAttestState("1"), lines[1:2], ima_keyrings=keyrings)
        self.assertTrue(failure)

        # add key for 2nd entry; 1st & 2nd entries must be verifiable
        eckeyfile = os.path.join(keydir, "secp256k1.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(eckeyfile)
        assert pubkey is not None
        tenant_keyring.add_pubkey(pubkey, keyidv2)
        _, failure = ima.process_measurement_list(AgentAttestState("1"), lines[0:2], ima_keyrings=keyrings)
        self.assertTrue(not failure)

    def test_ima_buf_verification(self):
        """The verification of ima-buf entries supporting keys loaded onto keyrings"""
        list_map = ima.process_ima_policy(ALLOWLIST, [])
        ima_keyrings = file_signatures.ImaKeyrings()

        self.assertTrue(
            ima.process_measurement_list(
                AgentAttestState("1"), KEYRINGS.splitlines(), json.dumps(list_map), ima_keyrings=ima_keyrings
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
            template_hash = codecs.decode(parts[1].encode("utf-8"), "hex")
            running_hash = hashlib.sha1(running_hash + template_hash).digest()
            pcrval = codecs.encode(running_hash, "hex").decode("utf-8")
            ima_hash, _ = ima.process_measurement_list(agentAttestState, [line], pcrval=pcrval)
            self.assertTrue(ima_hash == pcrval)

        # Feed empty iterative measurement list simulating 'no new measurement list entries' on attested system
        ima_hash, _ = ima.process_measurement_list(agentAttestState, [], pcrval=pcrval)
        self.assertTrue(ima_hash == pcrval)

    def test_mixed_verfication(self):
        """Test verification using allowlist and keys"""

        lists_map = ima.process_ima_policy(ALLOWLIST, [])
        lists_map_wrong = ima.process_ima_policy(ALLOWLIST_WRONG, [])
        lists_map_empty = ima.process_ima_policy(ALLOWLIST_EMPTY, [])
        lists_map_exclude = ima.process_ima_policy(ALLOWLIST, EXCLUDELIST)
        lists_map_exclude_wrong = ima.process_ima_policy(ALLOWLIST_WRONG, EXCLUDELIST)

        ima_keyrings = file_signatures.ImaKeyrings()
        empty_keyring = file_signatures.ImaKeyring()

        # every entry is covered by the allowlist and there's no keyring -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState("1"), COMBINED.splitlines(), json.dumps(lists_map))
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
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), COMBINED.splitlines(), ima_keyrings=ima_keyrings
        )
        self.assertTrue(failure)

        # all entries are either covered by allow list or by signature verification -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), COMBINED.splitlines(), json.dumps(lists_map), ima_keyrings=ima_keyrings
        )
        self.assertTrue(not failure)

        # the signature is valid but the hash in the allowlist is wrong -> this should fail
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), SIGNATURES.splitlines(), json.dumps(lists_map_wrong), ima_keyrings=ima_keyrings
        )
        self.assertTrue(failure)

        # the signature is valid and the file is not in the allowlist -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), SIGNATURES.splitlines(), json.dumps(lists_map_empty), ima_keyrings=ima_keyrings
        )
        self.assertTrue(not failure)

        # the signature is invalid but the correct hash is in the allowlist -> this should fail
        ima_keyrings.set_tenant_keyring(empty_keyring)
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), SIGNATURES.splitlines(), json.dumps(lists_map), ima_keyrings=ima_keyrings
        )
        self.assertTrue(failure)

        # the file has no signature but the hash is correct -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), MEASUREMENTS.splitlines(), json.dumps(lists_map)
        )
        self.assertTrue(not failure)

        # All files are in the exclude list but hashes are invalid -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), MEASUREMENTS.splitlines(), json.dumps(lists_map_exclude_wrong)
        )
        self.assertTrue(not failure)

        # All files are in the exclude list and their signatures are invalid -> this should pass
        ima_keyrings.set_tenant_keyring(tenant_keyring)
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"), SIGNATURES.splitlines(), json.dumps(lists_map_exclude), ima_keyrings=ima_keyrings
        )
        self.assertTrue(not failure)

        # All files are in the exclude list but hashes or signatures are invalid -> this should pass
        _, failure = ima.process_measurement_list(
            AgentAttestState("1"),
            MEASUREMENTS.splitlines(),
            json.dumps(lists_map_exclude_wrong),
            ima_keyrings=ima_keyrings,
        )
        self.assertTrue(not failure)

    def test_read_allowlist(self):
        """Test reading and processing of the IMA allow-list"""

        curdir = os.path.dirname(os.path.abspath(__file__))
        allowlist_file = os.path.join(curdir, "data", "ima-allowlist-short.txt")
        allowlist_sig = os.path.join(curdir, "data", "ima-allowlist-short.sig")
        allowlist_bad_sig = os.path.join(curdir, "data", "ima-allowlist-bad.sig")
        allowlist_gpg_key = os.path.join(curdir, "data", "gpg-sig.pub")
        allowlist_checksum = "6b010e359bbcebafb9b3e5010c302c94d29e249f86ae6293339506041aeebd41"
        allowlist_bad_checksum = "4c143670836f96535d9e617359b4d87c59e89e633e2773b4d7feae97f561b3dc"

        # simple read, no fancy verification
        al_bundle = ima.read_allowlist(allowlist_file)
        self.assertIsNotNone(al_bundle, "IMA policy bundle data is present")
        self.assertIsNotNone(al_bundle.get("ima_policy", None), "AllowList data is present in bundle")

        # unbundle and test output
        al_data = ima.unbundle_ima_policy(al_bundle, verify=False)
        self.assertIsNotNone(al_data["meta"], "AllowList metadata is present")
        self.assertEqual(al_data["meta"]["version"], 5, "AllowList metadata version is correct")
        self.assertEqual(
            al_data["meta"]["generator"],
            ima.IMA_POLICY_GENERATOR.LegacyAllowList,
            "AllowList metadata generator is correct",
        )

        self.assertIsNotNone(al_data["meta"].get("checksum", None), "AllowList checksum is present")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(
            al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0],
            "68e1d012e3f193dcde955e6ffbbc80e22b0f8778",
            "AllowList sample hash is correct",
        )
        self.assertIsNotNone(al_data["keyrings"], "AllowList keyrings are present")
        self.assertEqual(len(al_data["keyrings"]), 1, "AllowList keyrings are correct length")
        self.assertEqual(
            al_data["keyrings"][".ima"][0],
            "a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a",
            "AllowList sample keyring is correct",
        )

        # validate checksum
        al_bundle = ima.read_allowlist(allowlist_file, allowlist_checksum)
        self.assertIsNotNone(al_bundle, "IMA policy bundle data is present")
        self.assertIsNotNone(al_bundle.get("ima_policy", None), "AllowList data is present in bundle")
        self.assertIsNotNone(al_bundle.get("checksum", None), "AllowList checksum is present in bundle")

        # unbundle and test output
        al_data = ima.unbundle_ima_policy(al_bundle, verify=False)
        self.assertEqual(al_data["meta"]["checksum"], allowlist_checksum, "AllowList metadata correct checksum")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(
            al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0],
            "68e1d012e3f193dcde955e6ffbbc80e22b0f8778",
            "AllowList sample hash is correct",
        )

        # test with a bad checksum
        with self.assertRaises(Exception) as bad_checksum_context:
            ima.read_allowlist(allowlist_file, allowlist_bad_checksum)
        self.assertIn("Checksum of allowlist does not match", str(bad_checksum_context.exception))

        # validate GPG signature
        al_bundle = ima.read_allowlist(allowlist_file, None, allowlist_sig, allowlist_gpg_key)
        self.assertIsNotNone(al_bundle, "IMA policy bundle data is present")
        self.assertIsNotNone(al_bundle.get("ima_policy", None), "AllowList data is present in bundle")
        self.assertIsNotNone(al_bundle.get("key", None), "AllowList signing key is present in bundle")
        self.assertIsNotNone(al_bundle.get("sig", None), "AllowList signature is present in bundle")

        # unbundle and test output
        al_data = ima.unbundle_ima_policy(al_bundle, verify=True)
        self.assertIsNotNone(al_data["meta"].get("checksum", None), "AllowList checksum is present")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(
            al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0],
            "68e1d012e3f193dcde955e6ffbbc80e22b0f8778",
            "AllowList sample hash is correct",
        )

        # test with a bad GPG sig (tenant-side)
        with self.assertRaises(Exception) as bad_sig_context:
            ima.read_allowlist(allowlist_file, None, allowlist_bad_sig, allowlist_gpg_key)
        self.assertIn("Allowlist signature verification failed", str(bad_sig_context.exception))

        # test with a bad GPG sig (verifier-side)
        with open(allowlist_bad_sig, "rb") as bad_sig_f:
            bad_sig_raw = bad_sig_f.read()
        al_bundle["sig"] = base64.b64encode(bad_sig_raw).decode()
        with self.assertRaises(ima.SignatureValidationError) as bad_sig_context:
            ima.unbundle_ima_policy(al_bundle, verify=True)
        self.assertIn("Signature verification for allowlist failed!", str(bad_sig_context.exception.message))

        # validate everything together
        al_bundle = ima.read_allowlist(allowlist_file, allowlist_checksum, allowlist_sig, allowlist_gpg_key)
        self.assertIsNotNone(al_bundle, "IMA policy bundle data is present")
        self.assertIsNotNone(al_bundle.get("ima_policy", None), "AllowList data is present in bundle")
        self.assertIsNotNone(al_bundle.get("checksum", None), "AllowList checksum is present in bundle")
        self.assertIsNotNone(al_bundle.get("key", None), "AllowList signing key is present in bundle")
        self.assertIsNotNone(al_bundle.get("sig", None), "AllowList signature is present in bundle")

        # unbundle and test output
        al_data = ima.unbundle_ima_policy(al_bundle, verify=True)
        self.assertEqual(al_data["meta"]["checksum"], allowlist_checksum, "AllowList metadata correct checksum")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(
            al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0],
            "68e1d012e3f193dcde955e6ffbbc80e22b0f8778",
            "AllowList sample hash is correct",
        )
