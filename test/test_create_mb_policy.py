"""
SPDX-License-Identifier: Apache-2.0
Copyright 2024 Red Hat, Inc.
"""

import argparse
import os
import unittest

from keylime.policy import create_mb_policy

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "create-mb-policy"))


class CreateMeasuredBootPolicy_Test(unittest.TestCase):
    def test_event_to_sha256(self):
        test_cases = [
            {"event": {"Digests": [{"AlgorithmId": "sha256", "Digest": "foobar"}]}, "expected": {"sha256": "0xfoobar"}},
            {
                "event": {
                    "Digests": [
                        {
                            "AlgorithmId": "sha256",
                            "Digest": "5a16d6659724873d146bdb8cf1c9f9fdb5473040107f16493fd2051ca71a1227",
                        }
                    ]
                },
                "expected": {"sha256": "0x5a16d6659724873d146bdb8cf1c9f9fdb5473040107f16493fd2051ca71a1227"},
            },
            {"event": "bogus", "expected": {}},
            {"event": {}, "expected": {}},
            {"event": {"Digests": [{"Digest": "foobar"}]}, "expected": {}},
        ]

        for c in test_cases:
            self.assertDictEqual(create_mb_policy.event_to_sha256(c["event"]), c["expected"])

    def test_get_s_crtm(self):
        field = "scrtm"
        test_cases = [
            {"events": [], "expected": {}},
            {"events": "foobar", "expected": {}},
            {"events": [{}, {"EventType": "not this one"}], "expected": {}},
            {"events": [{}, {"EventType": "EV_S_CRTM_VERSION"}], "expected": {field: {}}},
            {
                "events": [
                    {},
                    {"EventType": "EV_S_CRTM_VERSION", "Digests": [{"AlgorithmId": "sha1", "Digest": "foobar"}]},
                ],
                "expected": {field: {}},
            },
            {
                "events": [
                    {},
                    {
                        "EventType": "EV_S_CRTM_VERSION",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "5a16d6659724873d146bdb8cf1c9f9fdb5473040107f16493fd2051ca71a1227",
                            }
                        ],
                    },
                ],
                "expected": {field: {"sha256": "0x5a16d6659724873d146bdb8cf1c9f9fdb5473040107f16493fd2051ca71a1227"}},
            },
        ]

        for c in test_cases:
            self.assertDictEqual(create_mb_policy.get_s_crtm(c["events"]), c["expected"])

    def test_get_platform_firmware(self):
        field = "platform_firmware"
        test_cases = [
            {"events": [], "expected": {field: []}},
            {"events": "foobar", "expected": {field: []}},
            {"events": [{}, {"EventType": "not this one"}], "expected": {field: []}},
            {"events": [{}, {"EventType": "EV_S_CRTM_VERSION"}], "expected": {field: []}},
            {"events": [{}, {"EventType": "EV_EFI_PLATFORM_FIRMWARE_BLOB"}], "expected": {field: [{}]}},
            {
                "events": [
                    {},
                    {
                        "EventType": "EV_EFI_PLATFORM_FIRMWARE_BLOB",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "5a16d6659724873d146bdb8cf1c9f9fdb5473040107f16493fd2051ca71a1227",
                            }
                        ],
                    },
                ],
                "expected": {field: [{"sha256": "0x5a16d6659724873d146bdb8cf1c9f9fdb5473040107f16493fd2051ca71a1227"}]},
            },
            {"events": [{}, {"EventType": "EV_EFI_PLATFORM_FIRMWARE_BLOB2"}], "expected": {field: [{}]}},
            {
                "events": [
                    {},
                    {
                        "EventType": "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "5a16d6659724873d146bdb8cf1c9f9fdb5473040107f16493fd2051ca71a1227",
                            }
                        ],
                    },
                ],
                "expected": {field: [{"sha256": "0x5a16d6659724873d146bdb8cf1c9f9fdb5473040107f16493fd2051ca71a1227"}]},
            },
        ]

        for c in test_cases:
            self.assertDictEqual(create_mb_policy.get_platform_firmware(c["events"]), c["expected"])

    def test_variabledata_to_signature(self):
        test_cases = [
            {"data": [], "expected": []},
            {"data": ["foobar"], "expected": []},
            {"data": [{"Keys": []}], "expected": []},
            {"data": [{"Keys": [{}]}], "expected": []},
            {"data": [{"Keys": "foobar"}], "expected": []},
            {"data": [{"Keys": [{"SignatureOwner": "sig-owner"}]}], "expected": []},
            {"data": [{"Keys": [{"SignatureData": "sig-data"}]}], "expected": []},
            {
                "data": [{"Keys": [{"SignatureOwner": "sig-owner", "SignatureData": "sig-data"}]}],
                "expected": [{"SignatureData": "0xsig-data", "SignatureOwner": "sig-owner"}],
            },
        ]

        for c in test_cases:
            self.assertListEqual(create_mb_policy.variabledata_to_signature(c["data"]), c["expected"])

    def test_get_keys(self):
        test_cases = [
            {"events": [], "expected": {"db": [], "dbx": [], "kek": [], "pk": []}},
            {
                "events": [
                    {
                        "EventNum": 12,
                        "PCRIndex": 7,
                        "EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "115aa827dbccfb44d216ad9ecfda56bdea620b860a94bed5b7a27bba1c4d02d8",
                            }
                        ],
                        "Event": {"UnicodeName": "SecureBoot", "VariableData": {"Enabled": "No"}},
                    }
                ],
                "expected": {"db": [], "dbx": [], "kek": [], "pk": []},
            },
            # Good event!
            {
                "events": [
                    {
                        "EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "ddd2fe434fee03440d49850277556d148b75d7cafdc4dc59e8a67cccecad1a3e",
                            }
                        ],
                        "Event": {
                            "UnicodeName": "PK",
                            "VariableData": [
                                {
                                    "SignatureType": "sig-type",
                                    "Keys": [{"SignatureOwner": "sig-owner", "SignatureData": "sig-data"}],
                                }
                            ],
                        },
                    }
                ],
                "expected": {
                    "pk": [{"SignatureOwner": "sig-owner", "SignatureData": "0xsig-data"}],
                    "kek": [],
                    "db": [],
                    "dbx": [],
                },
            },
            # Missing  event["EventType"].
            {
                "events": [
                    {
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "ddd2fe434fee03440d49850277556d148b75d7cafdc4dc59e8a67cccecad1a3e",
                            }
                        ],
                        "Event": {
                            "UnicodeName": "PK",
                            "VariableData": [
                                {
                                    "SignatureType": "sig-type",
                                    "Keys": [{"SignatureOwner": "sig-owner", "SignatureData": "sig-data"}],
                                }
                            ],
                        },
                    }
                ],
                "expected": {"db": [], "dbx": [], "kek": [], "pk": []},
            },
            # Bad event name, expected is EV_EFI_VARIABLE_DRIVER_CONFIG.
            {
                "events": [
                    {
                        "EventType": "WRONG_EVENT",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "ddd2fe434fee03440d49850277556d148b75d7cafdc4dc59e8a67cccecad1a3e",
                            }
                        ],
                        "Event": {
                            "UnicodeName": "PK",
                            "VariableData": [
                                {
                                    "SignatureType": "sig-type",
                                    "Keys": [{"SignatureOwner": "sig-owner", "SignatureData": "sig-data"}],
                                }
                            ],
                        },
                    }
                ],
                "expected": {"db": [], "dbx": [], "kek": [], "pk": []},
            },
            # Missing event["Event"].
            {
                "events": [
                    {
                        "EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "ddd2fe434fee03440d49850277556d148b75d7cafdc4dc59e8a67cccecad1a3e",
                            }
                        ],
                    }
                ],
                "expected": {"db": [], "dbx": [], "kek": [], "pk": []},
            },
            # Missing event["Event"]["UnicodeName"].
            {
                "events": [
                    {
                        "EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "ddd2fe434fee03440d49850277556d148b75d7cafdc4dc59e8a67cccecad1a3e",
                            }
                        ],
                        "Event": {
                            "VariableData": [
                                {
                                    "SignatureType": "sig-type",
                                    "Keys": [{"SignatureOwner": "sig-owner", "SignatureData": "sig-data"}],
                                }
                            ]
                        },
                    }
                ],
                "expected": {"db": [], "dbx": [], "kek": [], "pk": []},
            },
        ]
        for c in test_cases:
            self.assertDictEqual(create_mb_policy.get_keys(c["events"]), c["expected"])

    def test_secureboot_enabled(self):
        test_cases = [
            {"events": [], "expected": False},
            {
                "events": [
                    {
                        "EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                        "Event": {"UnicodeName": "SecureBoot", "VariableData": {"Enabled": "Yes"}},
                    }
                ],
                "expected": True,
            },
            {
                "events": [
                    {
                        "EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                        "Event": {"UnicodeName": "SecureBoot", "VariableData": {"Enabled": "No"}},
                    }
                ],
                "expected": False,
            },
            # No variable data.
            {
                "events": [{"EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG", "Event": {"UnicodeName": "SecureBoot"}}],
                "expected": False,
            },
            # Bad event.
            {
                "events": [
                    {
                        "EventType": "WRONG_EVENT",
                        "Event": {"UnicodeName": "SecureBoot", "VariableData": {"Enabled": "Yes"}},
                    }
                ],
                "expected": False,
            },
            # No EventType.
            {
                "events": [{"Event": {"UnicodeName": "SecureBoot", "VariableData": {"Enabled": "No"}}}],
                "expected": False,
            },
        ]

        for c in test_cases:
            self.assertEqual(create_mb_policy.secureboot_enabled(c["events"]), c["expected"])

    def test_get_mok(self):
        test_cases = [
            {"events": [], "expected": {"mokdig": [], "mokxdig": []}},
            {
                "events": [
                    {
                        "EventType": "EV_IPL",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest"}],
                        "Event": {"String": "MokListX"},
                    }
                ],
                "expected": {"mokdig": [], "mokxdig": [{"sha256": "0xdigest"}]},
            },
            {
                "events": [
                    {
                        "EventType": "EV_IPL",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest"}],
                        "Event": {"String": "MokList"},
                    }
                ],
                "expected": {"mokdig": [{"sha256": "0xdigest"}], "mokxdig": []},
            },
            # No EventType.
            {
                "events": [
                    {"Digests": [{"AlgorithmId": "sha256", "Digest": "digest"}], "Event": {"String": "MokList"}}
                ],
                "expected": {"mokdig": [], "mokxdig": []},
            },
            # No event.
            {
                "events": [{"EventType": "EV_IPL", "Digests": [{"AlgorithmId": "sha256", "Digest": "digest"}]}],
                "expected": {"mokdig": [], "mokxdig": []},
            },
            # No event["Event"]["String"].
            {
                "events": [
                    {"EventType": "EV_IPL", "Digests": [{"AlgorithmId": "sha256", "Digest": "digest"}], "Event": {}}
                ],
                "expected": {"mokdig": [], "mokxdig": []},
            },
        ]

        for c in test_cases:
            self.assertDictEqual(create_mb_policy.get_mok(c["events"]), c["expected"])

    def test_get_kernel(self):
        test_cases = [
            {"events": [], "secureboot": False, "expected": {}},
            # No secure boot.
            {
                "events": [
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-2"}],
                        "Event": {
                            "DevicePath": "PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,00-25-38-B2-21-D1-37-50)/HD(1,GPT,b8f6bee9-bc10-4c72-b34a-6db8fd8f772c,0x800,0x80000)/\\EFI\fedora\\shimx64.efi"
                        },
                    },
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-3"}],
                        "Event": {"DevicePath": "\\EFI\fedora\\grubx64.efi"},
                    },
                ],
                "secureboot": False,
                "expected": {"kernels": [{"shim_authcode_sha256": "0xdigest-2", "grub_authcode_sha256": "0xdigest-3"}]},
            },
            # Similar to the previous one, but now it also has an
            # application mathcing a a path that should be ignored
            # as we have no reference value for it.
            {
                "events": [
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest1"}],
                        "Event": {
                            "DevicePath": "FvVol(8fc151ae-c96f-4bc9-8c33-107992c7735b)/FvFile(821aca26-29ea-4993-839f-597fc021708d)"
                        },
                    },
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-2"}],
                        "Event": {
                            "DevicePath": "PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,00-25-38-B2-21-D1-37-50)/HD(1,GPT,b8f6bee9-bc10-4c72-b34a-6db8fd8f772c,0x800,0x80000)/\\EFI\fedora\\shimx64.efi"
                        },
                    },
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-3"}],
                        "Event": {"DevicePath": "\\EFI\fedora\\grubx64.efi"},
                    },
                    {
                        "PCRIndex": 9,
                        "EventType": "EV_IPL",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-4"}],
                        "Event": {"String": "(hd0,gpt2)/vmlinuz-5.14.0-347.el9.x86_64"},
                    },
                    {
                        "PCRIndex": 8,
                        "EventType": "EV_IPL",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "digest-5",
                            }
                        ],
                        "Event": {
                            "String": "kernel_cmdline: (hd0,gpt2)/vmlinuz-5.14.0-347.el9.x86_64 root=UUID=f0e4ae11-6b98-42f9-ab3b-3b962e8b4253 ro resume=UUID=ba40b3f3-e38d-42f7-8f81-4394e84f41a6 console=ttyS0,115200 ima_appraise=fix ima_canonical_fmt ima_policy=tcb ima_template=ima-ng"
                        },
                    },
                ],
                "secureboot": False,
                "expected": {
                    "kernels": [
                        {
                            "shim_authcode_sha256": "0xdigest-2",
                            "grub_authcode_sha256": "0xdigest-3",
                            "vmlinuz_plain_sha256": "0xdigest-4",
                            "kernel_cmdline": "\\(hd0,gpt2\\)/vmlinuz\\-5\\.14\\.0\\-347\\.el9\\.x86_64\\ root=UUID=f0e4ae11\\-6b98\\-42f9\\-ab3b\\-3b962e8b4253\\ ro\\ resume=UUID=ba40b3f3\\-e38d\\-42f7\\-8f81\\-4394e84f41a6\\ console=ttyS0,115200\\ ima_appraise=fix\\ ima_canonical_fmt\\ ima_policy=tcb\\ ima_template=ima\\-ng",
                        }
                    ]
                },
            },
            # Only one UEFI application; 2 are expected.
            {
                "events": [
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-2"}],
                        "Event": {
                            "DevicePath": "PciRoot(0x0)/Pci(0x6,0x0)/Pci(0x0,0x0)/NVMe(0x1,00-25-38-B2-21-D1-37-50)/HD(1,GPT,b8f6bee9-bc10-4c72-b34a-6db8fd8f772c,0x800,0x80000)/\\EFI\fedora\\shimx64.efi"
                        },
                    }
                ],
                "secureboot": False,
                "expected": {},
            },
            # Now with Secure Boot.
            {
                "events": [
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-1"}],
                        "Event": {
                            "DevicePath": "PciRoot(0x0)/Pci(0x2,0x3)/Pci(0x0,0x0)/HD(1,GPT,a88ed452-9a52-45c4-91ce-3da7707caaab,0x800,0x12c000)/\\EFI\redhat\\shimx64.efi"
                        },
                    },
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-2"}],
                        "Event": {"DevicePath": "\\EFI\redhat\\grubx64.efi"},
                    },
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-3"}],
                        "Event": {"DevicePath": ""},
                    },
                    {
                        "EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "digest-4",
                            }
                        ],
                        "Event": {
                            "UnicodeName": "SecureBoot",
                            "VariableData": {"Enabled": "Yes"},
                        },
                    },
                    {
                        "PCRIndex": 9,
                        "EventType": "EV_IPL",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-5"}],
                        "Event": {"String": "(hd0,gpt2)/initramfs-5.14.0-347.el9.x86_64.img"},
                    },
                ],
                "secureboot": True,
                "expected": {
                    "kernels": [
                        {
                            "kernel_authcode_sha256": "0xdigest-3",
                            "shim_authcode_sha256": "0xdigest-1",
                            "grub_authcode_sha256": "0xdigest-2",
                            "initrd_plain_sha256": "0xdigest-5",
                        }
                    ]
                },
            },
            # Secure Boot with only 2 applications (shim, kernel), without
            # grub. 3 are expected.
            {
                "events": [
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-1"}],
                        "Event": {
                            "DevicePath": "PciRoot(0x0)/Pci(0x2,0x3)/Pci(0x0,0x0)/HD(1,GPT,a88ed452-9a52-45c4-91ce-3da7707caaab,0x800,0x12c000)/\\EFI\redhat\\shimx64.efi"
                        },
                    },
                    {
                        "EventType": "EV_EFI_BOOT_SERVICES_APPLICATION",
                        "Digests": [{"AlgorithmId": "sha256", "Digest": "digest-3"}],
                        "Event": {"DevicePath": ""},
                    },
                    {
                        "EventType": "EV_EFI_VARIABLE_DRIVER_CONFIG",
                        "Digests": [
                            {
                                "AlgorithmId": "sha256",
                                "Digest": "digest-4",
                            }
                        ],
                        "Event": {
                            "UnicodeName": "SecureBoot",
                            "VariableData": {"Enabled": "Yes"},
                        },
                    },
                ],
                "secureboot": True,
                "expected": {},
            },
        ]

        for c in test_cases:
            self.assertEqual(create_mb_policy.secureboot_enabled(c["events"]), c["secureboot"])
            self.assertDictEqual(create_mb_policy.get_kernel(c["events"], c["secureboot"]), c["expected"])

    def test_create_mb_refstate(self):
        # Create an argument parser.
        parent_parser = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser()
        subparser = main_parser.add_subparsers(title="actions")
        parser = create_mb_policy.get_arg_parser(subparser, parent_parser)

        event_log_secureboot_enabled = os.path.join(DATA_DIR, "binary_bios_measurements-secureboot")
        event_log_secureboot_disabled = os.path.join(DATA_DIR, "binary_bios_measurements")
        event_log_bogus = os.path.join(DATA_DIR, "binary_bios_measurements-bogus")
        event_log_empty = os.path.join(DATA_DIR, "binary_bios_measurements-empty")

        test_cases = [
            {"valid": False, "missing_params": True},
            {"valid": True, "missing_params": False, "-e": event_log_secureboot_enabled},
            {"valid": False, "missing_params": False, "-e": event_log_bogus},
            {"valid": False, "missing_params": False, "-e": event_log_empty},
            # The next one has secure boot disabled but we will not
            # indicate it (hence, it will not provide the -i flag),
            # so it should fail.
            {"valid": False, "missing_params": False, "-e": event_log_secureboot_disabled},
            # Now let's indicate secure boot is disabled.
            {"valid": True, "missing_params": False, "-e": event_log_secureboot_disabled, "secureboot_disabled": True},
            # And now we have a log with secure boot enabled, but let's
            # indicate it has it disabled, and it would be valid, but we
            # would get a warning.
            {"valid": True, "missing_params": False, "-e": event_log_secureboot_enabled, "secureboot_disabled": True},
        ]

        for case in test_cases:
            expected = case["valid"]
            del case["valid"]
            missing_params = case["missing_params"]
            del case["missing_params"]
            secureboot_disabled = case.get("secureboot_disabled")
            if secureboot_disabled:
                del case["secureboot_disabled"]

            # pylint: disable=consider-using-dict-items
            cli_args = " ".join(f"{arg} {case[arg]}" for arg in case).split()

            if secureboot_disabled:
                cli_args.append("-i")

            args = None
            if missing_params:
                # When required params are missing, it exits with with SystemExit.
                with self.assertRaises(SystemExit):
                    args = parser.parse_args(cli_args)
            else:
                args = parser.parse_args(cli_args)
                self.assertTrue(args is not None)

                mb_policy = create_mb_policy.create_mb_refstate(args)
                self.assertEqual(mb_policy is not None, expected, msg=f"args = {args}")
