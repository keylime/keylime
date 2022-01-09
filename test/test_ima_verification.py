'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 IBM Corporation
'''

import codecs
import hashlib
import os
import unittest

from keylime import json
from keylime.ima import ima, file_signatures
from keylime.agentstates import AgentAttestState

# BEGIN TEST DATA

ALLOWLIST = {
    "meta": {
        "version": 6,
    },
    "hashes": {
        'boot_aggregate': ['e4cb9f5709c88376b5fc3743cd88e76b9aae8f3d992d845678de5215edb31216'],
        '/lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko': ['f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e'],
        '/lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko': ['cd026b58efdf66658685430ff526490d54a430a3f0066a35ac26a8acab66c55d'],
        '/usr/bin/dd': ['1350320e5f7f51553bac8aa403489a1b135bc101'],
        '/usr/bin/zmore': ['1cb84b12db45d7da8de58ba6744187db84082f0e'],
        '/usr/bin/zless': ['233ad3a8e77c63a7d9a56063ec2cad1eafa58850'],
    },
    "keyrings": {
        '.ima':  ['a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a'],
    },
    "ima": {
        "dm_policy": None
    }
}

ALLOWLIST_EMPTY = {
    "meta": {
        "version": 1,
    },
    "hashes": {}
}

# Allowlist with different hashes
ALLOWLIST_WRONG = {
    "meta": {
        "version": 1,
    },
    "hashes": {
        '/usr/bin/dd': ['1350320e5f7f51553bac8aa403489a1b135bc102'],
        '/usr/bin/zmore': ['1cb84b12db45d7da8de58ba6744187db84082f01']
    }
}

EXCLUDELIST = [
    "boot_aggregate",
    "/lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko",
    "/lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko",
    "/usr/bin/dd",
    "/usr/bin/zmore",
    "/usr/bin/zless"
]

MEASUREMENTS = \
    '10 0c8a706a75a5689c1e168f0a573a3cbec33061b5 ima-sig sha256:e4cb9f5709c88376b5fc3743cd88e76b9aae8f3d992d845678de5215edb31216 boot_aggregate\n'\
    '10 5426cf3031a43f5bfca183d79950698a95a728f6 ima-sig sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e /lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko\n'\
    '10 f8a7b32dba2cb3a5437786d7f9d5caee8db3115b ima-sig sha256:cd026b58efdf66658685430ff526490d54a430a3f0066a35ac26a8acab66c55d /lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko\n'

# 1st signature: RSA
# 2nd signature: EC
SIGNATURES = \
    '10 50873c47693cf9458e87eb4a02dd4f594f7a0c0f ima-sig sha1:1350320e5f7f51553bac8aa403489a1b135bc101 /usr/bin/dd 030202f3452d23010084c2a6cf7de1aeefa119220df0da265a7c44d34380f0d97002e7c778d09cfcf88c018e6595df3ee70eda926851f159332f852e7981a8fca1bc5e959958d06d234a0896861f13cc60da825905c8ed234df26c1deecfa816d5aa9bfb11b905e2814084a86b588be60423afada8dd0dd5a143774c6d890b64195ac42fb47ef5a9a00f0d6c80711d8e0c2b843ec38c02f60fd46bc46c7b4c329ad2dbb1b7625293703f9c739dc4c2bf0769126a2f3cb2cd031d1881cd0af64bf20fd474a993b48620f103a5c14999a2f17d60721bcc019a896b4138a688a59f50cb6cd94a4cfe3b8052e82dec025fef4feabb08c7ce412e3de850f903797e293ec27c329f57fd84e0\n'\
    '10 06e804489a77ddab51b9ef27e17053c0e5d503bd ima-sig sha1:1cb84b12db45d7da8de58ba6744187db84082f0e /usr/bin/zmore 030202531f402500483046022100bff9c02dc7b270c83cc94bfec10eecd42831de2cdcb04f024369a14623bc3a91022100cc4d015ae932fb98d6846645ed7d1bb1afd4621ec9089bc087126f191886dd31\n'

COMBINED = MEASUREMENTS + SIGNATURES

KEYRINGS = \
    '10 978351440c6c8a17568f0c366b9ede28efd14f8c ima-buf sha256:a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a .ima 308201d130820178a003020102020101300906072a8648ce3d0401301b3119301706035504030c1054657374696e672d45434453412d4341301e170d3231303631313133353831365a170d3232303631313133353831365a3021311f301d06035504030c1665636473612d63612d7369676e65642d65632d6b65793059301306072a8648ce3d020106082a8648ce3d030107034200044ce55be36765b59de2767f6d6721be8bea8e3db4ccc25ab76c30f5d1c11752ae1699cc39d31b378f69fecbe65ce1eb09e075f840fe4c052bafb9039742b76202a381a73081a430090603551d1304023000301d0603551d0e04160414b6fb3c083d19695be441c5f59afb95742cb6058c30560603551d23044f304d80140a51da379e45bd7ac623c3f765b53e1e2dde5195a11fa41d301b3119301706035504030c1054657374696e672d45434453412d434182142bb351b0d645e4d8594316ac3c96fc6d9c83791530130603551d25040c300a06082b06010505070302300b0603551d0f040403020780300906072a8648ce3d04010348003045022033d47b623c9feefab7d6e68b001ac6463433f99b61ce7b951a32da065a5d17af022100f3d73e38070053aec63a941ed36ae0dcfa25ed9cd538c459732a7e782132a4ca'

# END TEST DATA


class TestIMAVerification(unittest.TestCase):
    """ Test the IMA measurement list verification """

    def test_measurment_verification(self):
        """ Test IMA measurement list verification """
        lines = MEASUREMENTS.splitlines()
        lists_map = ima.process_allowlists(ALLOWLIST, '')
        lists_map_empty = ima.process_allowlists(ALLOWLIST_EMPTY, '')

        _, failure = ima.process_measurement_list(AgentAttestState('1'), lines)
        self.assertTrue(not failure,
                        "Validation should always work when no allowlist and no keyring is specified")

        _, failure = ima.process_measurement_list(AgentAttestState('1'), lines, lists_map)
        self.assertTrue(not failure)
        # test with list with JSON
        _, failure = ima.process_measurement_list(AgentAttestState('1'), lines, json.dumps(lists_map))
        self.assertTrue(not failure)

        # No files are in the allowlist -> this should fail
        _, failure = ima.process_measurement_list(AgentAttestState('1'), lines, lists_map_empty)
        self.assertTrue(failure)

    def test_signature_verification(self):
        """ Test the signature verification """
        curdir = os.path.dirname(os.path.abspath(__file__))
        keydir = os.path.join(curdir, "data", "ima_keys")

        lines = SIGNATURES.split('\n')

        # empty keyring
        keyrings = file_signatures.ImaKeyrings()
        _, failure = ima.process_measurement_list(AgentAttestState('1'), lines, ima_keyrings=keyrings)
        self.assertTrue(failure)

        tenant_keyring = file_signatures.ImaKeyring()
        keyrings.set_tenant_keyring(tenant_keyring)

        # add key for 1st entry; 1st entry must be verifiable
        rsakeyfile = os.path.join(keydir, "rsa2048pub.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(rsakeyfile)
        tenant_keyring.add_pubkey(pubkey, keyidv2)
        _, failure = ima.process_measurement_list(AgentAttestState('1'), lines[0:1], ima_keyrings=keyrings)
        self.assertTrue(not failure)
        _, failure = ima.process_measurement_list(AgentAttestState('1'), lines[1:2], ima_keyrings=keyrings)
        self.assertTrue(failure)

        # add key for 2nd entry; 1st & 2nd entries must be verifiable
        eckeyfile = os.path.join(keydir, "secp256k1.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(eckeyfile)
        tenant_keyring.add_pubkey(pubkey, keyidv2)
        _, failure = ima.process_measurement_list(AgentAttestState('1'), lines[0:2], ima_keyrings=keyrings)
        self.assertTrue(not failure)

    def test_ima_buf_verification(self):
        """ The verification of ima-buf entries supporting keys loaded onto keyrings """
        list_map = ima.process_allowlists(ALLOWLIST, '')
        ima_keyrings = file_signatures.ImaKeyrings()

        self.assertTrue(ima.process_measurement_list(AgentAttestState('1'), KEYRINGS.splitlines(), json.dumps(list_map), ima_keyrings=ima_keyrings) is not None)

    def test_iterative_attestation(self):
        """ Test that the resulting pcr value is as expected by subsequently feeding a measurement list.
            The AgentAtestState() will maintain the state of PCR 10.
        """

        lines = MEASUREMENTS.splitlines()
        agentAttestState = AgentAttestState('1')
        running_hash = agentAttestState.get_pcr_state(10)
        for line in lines:
            parts = line.split(' ')
            template_hash = codecs.decode(parts[1].encode("utf-8"), "hex")
            running_hash = hashlib.sha1(running_hash + template_hash).digest()
            pcrval = codecs.encode(running_hash, "hex").decode("utf-8")
            ima_hash, _ = ima.process_measurement_list(agentAttestState, [line], pcrval=pcrval)
            self.assertTrue(ima_hash == pcrval)

        # Feed empty iterative measurement list simulating 'no new measurement list entries' on attested system
        ima_hash, _ = ima.process_measurement_list(agentAttestState, [''], pcrval=pcrval)
        self.assertTrue(ima_hash == pcrval)

    def test_mixed_verfication(self):
        """ Test verification using allowlist and keys """

        lists_map = ima.process_allowlists(ALLOWLIST, '')
        lists_map_wrong = ima.process_allowlists(ALLOWLIST_WRONG, '')
        lists_map_empty = ima.process_allowlists(ALLOWLIST_EMPTY, '')
        lists_map_exclude = ima.process_allowlists(ALLOWLIST, EXCLUDELIST)
        lists_map_exclude_wrong = ima.process_allowlists(ALLOWLIST_WRONG, EXCLUDELIST)

        ima_keyrings = file_signatures.ImaKeyrings()
        empty_keyring = file_signatures.ImaKeyring()

        # every entry is covered by the allowlist and there's no keyring -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState('1'), COMBINED.splitlines(), json.dumps(lists_map))
        self.assertTrue(not failure)

        curdir = os.path.dirname(os.path.abspath(__file__))
        keydir = os.path.join(curdir, "data", "ima_keys")
        tenant_keyring = file_signatures.ImaKeyring()

        rsakeyfile = os.path.join(keydir, "rsa2048pub.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(rsakeyfile)
        tenant_keyring.add_pubkey(pubkey, keyidv2)

        eckeyfile = os.path.join(keydir, "secp256k1.pem")
        pubkey, keyidv2 = file_signatures.get_pubkey_from_file(eckeyfile)
        tenant_keyring.add_pubkey(pubkey, keyidv2)

        ima_keyrings.set_tenant_keyring(tenant_keyring)

        # entries are not covered by a exclude list -> this should fail
        _, failure = ima.process_measurement_list(AgentAttestState('1'), COMBINED.splitlines(), ima_keyrings=ima_keyrings)
        self.assertTrue(failure)

        # all entries are either covered by allow list or by signature verification -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState('1'), COMBINED.splitlines(), json.dumps(lists_map), ima_keyrings=ima_keyrings)
        self.assertTrue(not failure)

        # the signature is valid but the hash in the allowlist is wrong -> this should fail
        _, failure = ima.process_measurement_list(AgentAttestState('1'), SIGNATURES.splitlines(), json.dumps(lists_map_wrong), ima_keyrings=ima_keyrings)
        self.assertTrue(failure)

        # the signature is valid and the file is not in the allowlist -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState('1'), SIGNATURES.splitlines(), json.dumps(lists_map_empty), ima_keyrings=ima_keyrings)
        self.assertTrue(not failure)

        # the signature is invalid but the correct hash is in the allowlist -> this should fail
        ima_keyrings.set_tenant_keyring(empty_keyring)
        _, failure = ima.process_measurement_list(AgentAttestState('1'), SIGNATURES.splitlines(), json.dumps(lists_map), ima_keyrings=ima_keyrings)
        self.assertTrue(failure)

        # the file has no signature but the hash is correct -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState('1'), MEASUREMENTS.splitlines(), json.dumps(lists_map))
        self.assertTrue(not failure)

        # All files are in the exclude list but hashes are invalid -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState('1'), MEASUREMENTS.splitlines(), json.dumps(lists_map_exclude_wrong))
        self.assertTrue(not failure)

        # All files are in the exclude list and their signatures are invalid -> this should pass
        ima_keyrings.set_tenant_keyring(tenant_keyring)
        _, failure = ima.process_measurement_list(AgentAttestState('1'), SIGNATURES.splitlines(), json.dumps(lists_map_exclude), ima_keyrings=ima_keyrings)
        self.assertTrue(not failure)

        # All files are in the exclude list but hashes or signatures are invalid -> this should pass
        _, failure = ima.process_measurement_list(AgentAttestState('1'), MEASUREMENTS.splitlines(), json.dumps(lists_map_exclude_wrong), ima_keyrings=ima_keyrings)
        self.assertTrue(not failure)

    def test_read_allowlist(self):
        """ Test reading and processing of the IMA allow-list """

        curdir = os.path.dirname(os.path.abspath(__file__))
        allowlist_file = os.path.join(curdir, "data", "ima-allowlist-short.txt")
        allowlist_sig = os.path.join(curdir, "data", "ima-allowlist-short.sig")
        allowlist_bad_sig = os.path.join(curdir, "data", "ima-allowlist-bad.sig")
        allowlist_gpg_key = os.path.join(curdir, "data", "gpg-sig.pub")
        allowlist_checksum = "6b010e359bbcebafb9b3e5010c302c94d29e249f86ae6293339506041aeebd41"
        allowlist_bad_checksum = "4c143670836f96535d9e617359b4d87c59e89e633e2773b4d7feae97f561b3dc"

        # simple read, no fancy verification
        al_data = ima.read_allowlist(allowlist_file)
        self.assertIsNotNone(al_data, "AllowList data is present")
        self.assertIsNotNone(al_data["meta"], "AllowList metadata is present")
        self.assertEqual(al_data["meta"]["version"], 5, "AllowList metadata version is correct")
        self.assertEqual(al_data["meta"]["generator"], "keylime-legacy-format-upgrade", "AllowList metadata generator is correct")
        self.assertNotIn("checksum", al_data["meta"], "AllowList metadata no checksum")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0], "68e1d012e3f193dcde955e6ffbbc80e22b0f8778", "AllowList sample hash is correct")
        self.assertIsNotNone(al_data["keyrings"], "AllowList keyrings are present")
        self.assertEqual(len(al_data["keyrings"]), 1, "AllowList keyrings are correct length")
        self.assertEqual(al_data["keyrings"][".ima"][0], "a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a", "AllowList sample keyring is correct")

        # validate checkum
        al_data = ima.read_allowlist(allowlist_file, allowlist_checksum)
        self.assertIsNotNone(al_data, "AllowList data is present")
        self.assertEqual(al_data["meta"]["checksum"], allowlist_checksum, "AllowList metadata correct checksum")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0], "68e1d012e3f193dcde955e6ffbbc80e22b0f8778", "AllowList sample hash is correct")

        # test with a bad checksum
        with self.assertRaises(Exception) as bad_checksum_context:
            ima.read_allowlist(allowlist_file, allowlist_bad_checksum)
        self.assertIn('Checksum of allowlist does not match', str(bad_checksum_context.exception))

        # validate GPG signature
        al_data = ima.read_allowlist(allowlist_file, None, allowlist_sig, allowlist_gpg_key)
        self.assertIsNotNone(al_data, "AllowList data is present")
        self.assertNotIn("checksum", al_data["meta"], "AllowList metadata no checksum")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0], "68e1d012e3f193dcde955e6ffbbc80e22b0f8778", "AllowList sample hash is correct")

        # test with a bad GPG sig
        with self.assertRaises(Exception) as bad_sig_context:
            ima.read_allowlist(allowlist_file, None, allowlist_bad_sig, allowlist_gpg_key)
        self.assertIn('Allowlist signature verification failed', str(bad_sig_context.exception))

        # validate everything together
        al_data = ima.read_allowlist(allowlist_file, allowlist_checksum, allowlist_sig, allowlist_gpg_key)
        self.assertIsNotNone(al_data, "AllowList data is present")
        self.assertEqual(al_data["meta"]["checksum"], allowlist_checksum, "AllowList metadata correct checksum")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0], "68e1d012e3f193dcde955e6ffbbc80e22b0f8778", "AllowList sample hash is correct")
