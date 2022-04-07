'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Thore Sommer
'''

import unittest

from keylime.ima import ast
from keylime.failure import Failure, Component
from keylime.common.algorithms import Hash

# BEGIN TEST DATA

VALID_ENTRIES = {
    "ima-sig-rsa": (ast.ImaSig,
                    '10 50873c47693cf9458e87eb4a02dd4f594f7a0c0f ima-sig sha1:1350320e5f7f51553bac8aa403489a1b135bc101 /usr/bin/dd 030202f3452d23010084c2a6cf7de1aeefa119220df0da265a7c44d34380f0d97002e7c778d09cfcf88c018e6595df3ee70eda926851f159332f852e7981a8fca1bc5e959958d06d234a0896861f13cc60da825905c8ed234df26c1deecfa816d5aa9bfb11b905e2814084a86b588be60423afada8dd0dd5a143774c6d890b64195ac42fb47ef5a9a00f0d6c80711d8e0c2b843ec38c02f60fd46bc46c7b4c329ad2dbb1b7625293703f9c739dc4c2bf0769126a2f3cb2cd031d1881cd0af64bf20fd474a993b48620f103a5c14999a2f17d60721bcc019a896b4138a688a59f50cb6cd94a4cfe3b8052e82dec025fef4feabb08c7ce412e3de850f903797e293ec27c329f57fd84e0'),
    "ima-sig-ec": (ast.ImaSig,
                   '10 06e804489a77ddab51b9ef27e17053c0e5d503bd ima-sig sha1:1cb84b12db45d7da8de58ba6744187db84082f0e /usr/bin/zmore 030202531f402500483046022100bff9c02dc7b270c83cc94bfec10eecd42831de2cdcb04f024369a14623bc3a91022100cc4d015ae932fb98d6846645ed7d1bb1afd4621ec9089bc087126f191886dd31'),
    "ima-sig-missing": (ast.ImaSig,
                        '10 5426cf3031a43f5bfca183d79950698a95a728f6 ima-sig sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e /lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko'),
    "ima-buf": (ast.ImaBuf, "10 b7862dbbf1383ac6c7cca7f02d981a081aacb1f1 ima-buf sha1:6e0e6fc8a188ef4f059638949adca4d221946906 device_resume 6e616d653d544553543b757569643d43525950542d5645524954592d39656633326535623635623034343234613561386562343436636630653731332d544553543b63617061636974793d303b6d616a6f723d3235333b6d696e6f723d303b6d696e6f725f636f756e743d313b6e756d5f746172676574733d313b6163746976655f7461626c655f686173683d346565383065333365353635643336333430356634303238393436653837623365396563306335383661666639656630656436663561653762656237326431333b"),
    "ima": (ast.Ima, "10 d7026dc672344d3ee372217bdbc7395947788671 ima 6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e /usr/bin/kmod"),
    "ima-ng": (ast.ImaNg, "10 7936eb315fb4e74b99e7d461bc5c96049e1ee092 ima-ng sha1:bc026ae66d81713e4e852465e980784dc96651f8 /usr/lib/systemd/systemd"),
}

INVALID_ENTRIES = {
    "invalid-mode": "10 7936eb315fb4e74b99e7d461bc5c96049e1ee092 not-ima sha1:bc026ae66d81713e4e852465e980784dc96651f8 /usr/lib/systemd/systemd",
    "invalid-template-hash": "10 I936eb315fb4e74b99e7d461bc5c96049e1ee092 ima-ng sha1:bc026ae66d81713e4e852465e980784dc96651f8 /usr/lib/systemd/systemd",
    "invalid-digest": "10 7936eb315fb4e74b99e7d461bc5c96049e1ee092 ima-ng sha1:Ic026ae66d81713e4e852465e980784dc96651f8 /usr/lib/systemd/systemd",
    "not-ima-string": "this is text not an ima entry",
}

# END TEST DATA


def _true(*_):
    return Failure(Component.DEFAULT)


AlwaysTrueValidator = ast.Validator({
    ast.Ima: _true,
    ast.ImaNg: _true,
    ast.ImaSig: _true,
    ast.ImaBuf: _true
})


class TestImaAst(unittest.TestCase):

    def test_valid_entry_construction(self):
        hash_alg = Hash.SHA1
        for name, (expected_mode, data) in VALID_ENTRIES.items():
            err = None
            try:
                entry = ast.Entry(data, AlwaysTrueValidator, ima_hash_alg=hash_alg, pcr_hash_alg=hash_alg)
                self.assertTrue(entry.pcr == "10", f"Expected pcr 10 for {name}. Got: {entry.pcr}")
                self.assertTrue(isinstance(entry.mode, expected_mode)) # pylint: disable=isinstance-second-argument-not-valid-type
                self.assertTrue(entry.ima_template_hash == hash_alg.hash(entry.mode.bytes()),
                                f"Constructed hash of {name} does not match template hash.\n Expected: {entry.ima_template_hash}.\n Got: {entry.mode.bytes()}")
                self.assertTrue(not entry.invalid(), f"Entry of {name} couldn't be validated.")
            except ast.ParserError as e:
                err = e
            if err:
                self.fail(f"Constructing entry {name} failed with: {err}")

    def test_invalid_entries(self):
        for _, data in INVALID_ENTRIES.items():
            with self.assertRaises(ast.ParserError):
                ast.Entry(data)
