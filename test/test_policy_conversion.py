"""
SPDX-License-Identifier: Apache-2.0
Copyright 2022 Red Hat, Inc.
"""

import json
import tempfile
import unittest

from keylime.cmd import convert_ima_policy
from keylime.ima import ima

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
        "/usr/bin/dd": ["1350320e5f7f51553bac8aa403489a1b135bc101"],
        "/usr/bin/zmore": ["1cb84b12db45d7da8de58ba6744187db84082f0e"],
        "/usr/bin/zless": ["233ad3a8e77c63a7d9a56063ec2cad1eafa58850"],
    },
    "keyrings": {
        ".ima": ["a7d52aaa18c23d2d9bb2abb4308c0eeee67387a42259f4a6b1a42257065f3d5a"],
    },
    "ima": {"dm_policy": None},
}

EXCLUDELIST = """
boot_aggregate
/lib/modules/5.4.48-openpower1/kernel/drivers/usb/common/usb-common.ko
/lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko
/usr/bin/dd
/usr/bin/zmore
/usr/bin/zless
"""


class TestPolicyConversion(unittest.TestCase):
    """Test the policy conversion code"""

    def test_allowlist_conversion(self):
        with tempfile.NamedTemporaryFile() as tmp_allow:
            with open(tmp_allow.name, "w", encoding="utf8") as f:
                f.write(json.dumps(ALLOWLIST))
            created_ima_policy = convert_ima_policy.convert_legacy_allowlist(tmp_allow.name)
        self.assertIsNotNone(created_ima_policy["digests"], "Created IMA policy has 'digests' field")
        self.assertEqual(
            created_ima_policy["meta"]["version"], ima.IMA_POLICY_CURRENT_VERSION, "Metadata version is correct"
        )
        self.assertEqual(
            created_ima_policy["meta"]["generator"],
            ima.IMA_POLICY_GENERATOR.LegacyAllowList,
            "Metadata generator is correct",
        )
        self.assertEqual(
            created_ima_policy["digests"][
                "/lib/modules/5.4.48-openpower1/kernel/drivers/gpu/drm/drm_panel_orientation_quirks.ko"
            ][0],
            "cd026b58efdf66658685430ff526490d54a430a3f0066a35ac26a8acab66c55d",
            "Sample digest is correct",
        )

        with tempfile.NamedTemporaryFile() as tmp_exclude:
            with open(tmp_exclude.name, "w", encoding="utf8") as f:
                f.write(EXCLUDELIST)

            updated_ima_policy = convert_ima_policy.update_ima_policy(
                created_ima_policy, excludelist_path=tmp_exclude.name
            )
        self.assertIsNotNone(created_ima_policy["excludes"], "Created IMA policy has 'excludes' field")
        self.assertIn("/usr/bin/zmore", updated_ima_policy["excludes"], "Sample exclusion path is correct")
