import os
import unittest

from packaging.version import Version

from keylime.common.algorithms import Hash
from keylime.tpm.tpm_main import tpm

TPM2TOOLS_VERSION = Version(tpm().tools_version)

# ############################################################
# list of input challenges for get_tpm_manufacturer function
# ############################################################
tpm_manufacturer_tests = [
    # Infineon Optiga SLB9665'
    {
        "challenge": [
            b"TPM2_PT_MANUFACTURER:\n",
            b"  aw: 0x49465800\n",
            b'  value: "IFX"\n',
            b"TPM2_PT_VENDOR_STRING_1:\n",
            b"  raw: 0x534C4239\n",
            b'  value: "SLB9"\n',
            b"TPM2_PT_VENDOR_STRING_2:\n",
            b"  raw: 0x36363500\n",
            b'  value: "665"\n',
            b"TPM2_PT_VENDOR_STRING_3:\n",
            b"  raw: 0x0\n",
            b'  value: ""\n',
            b"TPM2_PT_VENDOR_STRING_4:\n",
            b"  raw: 0x0\n",
            b'  value: ""\n',
            b"TPM2_PT_VENDOR_TPM_TYPE:\n",
            b"  raw: 0x0\n",
        ],
        "response": "SLB9",
    },
    # Nuvoton device with a wrinkle: un-escaped double quotes in the manufacturer string
    #    'Nuvoton 75x unfixed': {
    #        'challenge': [
    #            b'TPM2_PT_MANUFACTURER:\n',    b'  raw: 0x4E544300\n', b'  value: "NTC"\n',
    #            b'TPM2_PT_VENDOR_STRING_1:\n', b'  raw: 0x4E504354\n', b'  value: "NPCT"\n',
    #            b'TPM2_PT_VENDOR_STRING_3:\n', b'  raw: 0x22212134\n', b'  value: ""!!4"\n'
    #        ],
    #        'response': 'NPCT'
    #    },
    # Nuvoton 75x, assuming tpm2-tools has escaped the quote side vendor string 3'
    {
        "challenge": [
            b"TPM2_PT_MANUFACTURER:\n",
            b"  raw: 0x4E544300\n",
            b'  value: "NTC"\n',
            b"TPM2_PT_VENDOR_STRING_1:\n",
            b"  raw: 0x4E504354\n",
            b'  value: "NPCT"\n',
            b"TPM2_PT_VENDOR_STRING_3:\n",
            b"  raw: 0x22212134\n",
            b'  value: "\\"!!4"\n',
        ],
        "response": "NPCT",
    },
    # Standard software TPM
    {
        "challenge": [
            b"TPM2_PT_VENDOR_STRING_1:\n",
            b"  raw: 0x53572020\n",
            b'  value: "SW"\n',
            b"TPM2_PT_VENDOR_STRING_2:\n",
            b"  raw: 0x2054504D\n",
            b'  value: "TPM"\n',
            b"TPM2_PT_VENDOR_STRING_3:\n",
            b"  raw: 0x0\n",
            b'  value: ""\n',
            b"TPM2_PT_VENDOR_STRING_4:\n",
            b"  raw: 0x0\n",
            b'  value: ""\n',
        ],
        "response": "SW",
    },
]


class TestTPM(unittest.TestCase):
    def setUp(self):
        self.tpm = tpm()

    # basic test:
    # whatever the underlying TPM is, just ensure get_manufacturer worked.
    # we cannot predict the output on the test system, so this test merely
    # ensures that the call to get_tpm_manufacturer succeeds.
    def test_get_tpm_manufacturer(self):
        """TPM sanity test"""
        self.tpm.get_tpm_manufacturer()

    def test_get_tpm_manufacturer_challenges(self):
        """Test the challenges in the list `tpm_manufacturer_tests`"""
        for test in tpm_manufacturer_tests:
            response = self.tpm.get_tpm_manufacturer(output=test["challenge"])
            self.assertEqual(test["response"], response)

    @unittest.skipIf(TPM2TOOLS_VERSION < Version("4.2"), "tpm_eventlog is not available")
    def test_parse_mb_bootlog(self):
        """Test parsing binary measured boot event log"""
        # Use the file that triggered https://github.com/keylime/keylime/issues/1153
        mb_log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/mb_log.b64"))
        with open(mb_log_path, encoding="utf-8") as f:
            # Read the base64 input and remove the newlines
            b64 = "".join(f.read().splitlines())
            pcr_hashes, boot_aggregates, measurement_data, failure = self.tpm.parse_mb_bootlog(b64, Hash.SHA256)

            self.assertFalse(
                failure, f"Parsing of measured boot log failed with: {list(map(lambda x: x.context, failure.events))}"
            )
            self.assertTrue(isinstance(pcr_hashes, dict))
            self.assertTrue(isinstance(boot_aggregates, dict))
            self.assertTrue(isinstance(measurement_data, dict))


if __name__ == "__main__":
    unittest.main()
