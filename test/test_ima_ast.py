"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Thore Sommer
"""

import unittest

from keylime.common.algorithms import Hash
from keylime.failure import Component, Failure
from keylime.ima import ast

# BEGIN TEST DATA

VALID_ENTRIES = {
    "ima-sig-rsa": (
        ast.ImaSig,
        "10 1e70a3e1af66f42826ad63b761b4cb9c4df195e1 ima-sig sha256:d33d5d13792292e202dbf69a6f1b07bc8a02f01424db8489ba7bb7d43c0290ef /usr/bin/dd 030204f3452d2301009dd340c852f37e35748363586939d4199b6684be27e7c1236ca1528f708372ed9cd52a0d991f66448790f5616ed5bd7f9bbd22193b1e3e54f6bf29a1497945a34d1b418b24f4cbeaef897bf3cebca27065ebb8761b46bc2662fe76f141245b9186a5ac8493c7f4976cf0d6dfc085c3e503e3f771bc3ccb121230db76fd8aba4f45f060ad64ab3afd99b4e52824b9eba12e93e46f9dcb2fa01d9cef89f298a0da02a82a4fb56924afd3e3c277a1302d99f770d488449df2d43eb5b174a0a528827e6877b965c2f0b7c89cf1aa26a7417a892df4c2294e2872d62748b72ea04ecb0689b5d792e615a9bf9d56f6e0f298560bf9441df0a22729c5f23389f028c25f",
    ),
    "ima-sig-ec": (
        ast.ImaSig,
        "10 5d4d5141ccd5066d50dc3f21d79ba02fedc24256 ima-sig sha256:b8ae0b8dd04a5935cd8165aa2260cd11b658bd71629bdb52256a675a1f73907b /usr/bin/zmore 030204531f402500483046022100fe24678d21083ead47660e1a2d553a592d777c478d1b0466de6ed484b54956b3022100cad3adb37f277bbb03544d6107751b4cd4f2289d8353fa36257400a99334d5c3",
    ),
    "ima-sig-missing": (
        ast.ImaSig,
        "10 5426cf3031a43f5bfca183d79950698a95a728f6 ima-sig sha256:f1125b940480d20ad841d26d5ea253edc0704b5ec1548c891edf212cb1a9365e /lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko ",
    ),
    "ima-buf": (
        ast.ImaBuf,
        "10 b7862dbbf1383ac6c7cca7f02d981a081aacb1f1 ima-buf sha1:6e0e6fc8a188ef4f059638949adca4d221946906 device_resume 6e616d653d544553543b757569643d43525950542d5645524954592d39656633326535623635623034343234613561386562343436636630653731332d544553543b63617061636974793d303b6d616a6f723d3235333b6d696e6f723d303b6d696e6f725f636f756e743d313b6e756d5f746172676574733d313b6163746976655f7461626c655f686173683d346565383065333365353635643336333430356634303238393436653837623365396563306335383661666639656630656436663561653762656237326431333b",
    ),
    "ima": (
        ast.Ima,
        "10 d7026dc672344d3ee372217bdbc7395947788671 ima 6f66d1d8e2fffcc12dfcb78c04b81fe5b8bbae4e /usr/bin/kmod",
    ),
    "ima-ng": (
        ast.ImaNg,
        "10 7936eb315fb4e74b99e7d461bc5c96049e1ee092 ima-ng sha1:bc026ae66d81713e4e852465e980784dc96651f8 /usr/lib/systemd/systemd",
    ),
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


AlwaysTrueValidator = ast.Validator({ast.Ima: _true, ast.ImaNg: _true, ast.ImaSig: _true, ast.ImaBuf: _true})


class TestImaAst(unittest.TestCase):
    def test_valid_entry_construction(self):
        hash_alg = Hash.SHA1
        for name, (expected_mode, data) in VALID_ENTRIES.items():
            err = None
            try:
                entry = ast.Entry(data, AlwaysTrueValidator, ima_hash_alg=hash_alg, pcr_hash_alg=hash_alg)
                self.assertTrue(entry.pcr == "10", f"Expected pcr 10 for {name}. Got: {entry.pcr}")
                self.assertTrue(
                    isinstance(entry.mode, expected_mode)  # pylint: disable=isinstance-second-argument-not-valid-type
                )
                self.assertTrue(
                    entry.ima_template_hash == hash_alg.hash(entry.mode.bytes()),
                    f"Constructed hash of {name} does not match template hash.\n Expected: {entry.ima_template_hash}.\n Got: {entry.mode.bytes()}",
                )
                self.assertTrue(not entry.invalid(), f"Entry of {name} couldn't be validated.")
            except ast.ParserError as e:
                err = e
            if err:
                self.fail(f"Constructing entry {name} failed with: {err}")

    def test_invalid_entries(self):
        for _, data in INVALID_ENTRIES.items():
            with self.assertRaises(ast.ParserError):
                ast.Entry(data)
