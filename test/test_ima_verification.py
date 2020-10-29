'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 IBM Corporation
'''

import os
import unittest

from keylime import ima
from keylime import ima_file_signatures

# BEGIN TEST DATA

ALLOWLIST = {
    "meta": {
        "version": 1,
    },
    "hashes": {
        'boot_aggregate': ['e4cb9f5709c88376b5fc3743cd88e76b9aae8f3d992d845678de5215edb31216'],
        '/lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko': ['f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e'],
        '/lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko': ['cd026b58efdf66658685430ff526490d54a430a3f0066a35ac26a8acab66c55d'],
        '/usr/bin/dd': ['1350320e5f7f51553bac8aa403489a1b135bc101'],
        '/usr/bin/zmore': ['1cb84b12db45d7da8de58ba6744187db84082f0e'],
        '/usr/bin/zless': ['233ad3a8e77c63a7d9a56063ec2cad1eafa58850'],
    }
}

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

# END TEST DATA


class TestIMAVerification(unittest.TestCase):
    """ Test the IMA measurement list verification """

    def test_measurment_verification(self):
        """ Test IMA measurement list verification """
        lines = MEASUREMENTS.splitlines()
        lists_map = ima.process_allowlists(ALLOWLIST, '')

        self.assertTrue(ima.process_measurement_list(lines, lists_map) is not None)
        # test with list as a string
        self.assertTrue(ima.process_measurement_list(lines, str(lists_map)) is not None)


    def test_signature_verification(self):
        """ Test the signature verification """
        curdir = os.path.dirname(os.path.abspath(__file__))
        keydir = os.path.join(curdir, "data", "ima_keys")

        lines = SIGNATURES.split('\n')

        # empty keyring
        keyring = ima_file_signatures.ImaKeyring()
        self.assertTrue(ima.process_measurement_list(lines, ima_keyring=keyring) is None)

        # add key for 1st entry; 1st entry must be verifiable
        rsakeyfile = os.path.join(keydir, "rsa2048pub.pem")
        pubkey = ima_file_signatures.get_pubkey_from_file(rsakeyfile)
        keyring.add_pubkey(pubkey)
        self.assertTrue(ima.process_measurement_list(lines[0:1], ima_keyring=keyring) is not None)
        self.assertTrue(ima.process_measurement_list(lines[1:2], ima_keyring=keyring) is None)

        # add key for 2nd entry; 1st & 2nd entries must be verifiable
        eckeyfile = os.path.join(keydir, "secp256k1.pem")
        pubkey = ima_file_signatures.get_pubkey_from_file(eckeyfile)
        keyring.add_pubkey(pubkey)
        self.assertTrue(ima.process_measurement_list(lines[0:2], ima_keyring=keyring) is not None)

    def test_mixed_verfication(self):
        """ Test verification using allowlist and keys """

        lists_map = ima.process_allowlists(ALLOWLIST, '')

        # every entry is covered by the allowlist and there's no keyring -> this should pass
        self.assertTrue(ima.process_measurement_list(COMBINED.splitlines(), str(lists_map)) is not None)

        curdir = os.path.dirname(os.path.abspath(__file__))
        keydir = os.path.join(curdir, "data", "ima_keys")
        keyring = ima_file_signatures.ImaKeyring()

        rsakeyfile = os.path.join(keydir, "rsa2048pub.pem")
        pubkey = ima_file_signatures.get_pubkey_from_file(rsakeyfile)
        keyring.add_pubkey(pubkey)

        eckeyfile = os.path.join(keydir, "secp256k1.pem")
        pubkey = ima_file_signatures.get_pubkey_from_file(eckeyfile)
        keyring.add_pubkey(pubkey)

        # entries are not covered by a exclude list -> this should fail
        self.assertTrue(ima.process_measurement_list(COMBINED.splitlines(), ima_keyring=keyring) is None)

        # all entries are either covered by exclude list or by signature verification -> this should pass
        self.assertTrue(ima.process_measurement_list(COMBINED.splitlines(), str(lists_map), ima_keyring=keyring) is not None)

    def test_read_allowlist(self):
        """ Test reading and processing of the IMA allow-list """

        curdir = os.path.dirname(os.path.abspath(__file__))
        allowlist_file = os.path.join(curdir, "data", "ima-allowlist-short.txt")
        allowlist_sig = os.path.join(curdir, "data", "ima-allowlist-short.sig")
        allowlist_bad_sig = os.path.join(curdir, "data", "ima-allowlist-bad.sig")
        allowlist_gpg_key = os.path.join(curdir, "data", "gpg-sig.pub")
        allowlist_checksum = "8b7c2c6a1d7af2568cc663905491bda829c04c397cdba38cc4fc4d8d8a3e69d4"
        allowlist_bad_checksum = "4c143670836f96535d9e617359b4d87c59e89e633e2773b4d7feae97f561b3dc"

        # simple read, no fancy verification
        al_data = ima.read_allowlist(allowlist_file)
        self.assertIsNotNone(al_data, "AllowList data is present")
        self.assertIsNotNone(al_data["meta"], "AllowList metadata is present")
        self.assertEqual(al_data["meta"]["version"], 1, "AllowList metadata version is correct")
        self.assertEqual(al_data["meta"]["generator"], "keylime-legacy-format-upgrade", "AllowList metadata generator is correct")
        self.assertNotIn("checksum", al_data["meta"], "AllowList metadata no checksum")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0], "68e1d012e3f193dcde955e6ffbbc80e22b0f8778", "AllowList sample hash is correct")

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
        self.assertIn('GPG signature verification failed', str(bad_sig_context.exception))

        # validate everything together
        al_data = ima.read_allowlist(allowlist_file, allowlist_checksum, allowlist_sig, allowlist_gpg_key)
        self.assertIsNotNone(al_data, "AllowList data is present")
        self.assertEqual(al_data["meta"]["checksum"], allowlist_checksum, "AllowList metadata correct checksum")
        self.assertIsNotNone(al_data["hashes"], "AllowList hashes are present")
        self.assertEqual(len(al_data["hashes"]), 21, "AllowList hashes are correct length")
        self.assertEqual(al_data["hashes"]["/boot/grub2/i386-pc/testload.mod"][0], "68e1d012e3f193dcde955e6ffbbc80e22b0f8778", "AllowList sample hash is correct")
