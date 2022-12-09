import re
import typing

from . import policies, tests

# The Example class is an example of a policy for checking boot event logs
# against reference state.  This policy checks:
# - that SecureBoot was enabled
# - that a good BIOS, shim, grub, and kernel were run
# - that only good keys are allowed
# - that all known bad keys are forbidden
# - the initial ramdisk contents and kernel command line were good
#
# This policy expects the reference state to be a dict created by `json.load`
# containing the following.
# scrtm_and_bios - list of allowed {
#    scrtm - digest for PCR 0 event type EV_S_CRTM_VERSION
#    platform_firmware - sequence of digest for PCR 0 event type EV_EFI_PLATFORM_FIRMWARE_BLOB
# }
# pk - list of allowed PK keys
# kek - list of allowed KEK keys
# db - list of allowed db keys
# dbx - list of required dbx keys
# mokdig - list of allowed digests of MoKList (PCR 14 EV_IPL)
# mokxdig - list of allowed digests of MoKListX (PCR 14 EV_IPL)
# kernels - list of allowed {
#   shim_authcode_sha256: 0xhex (for PCR 4 EV_EFI_BOOT_SERVICES_APPLICATION),
#   grub_authcode_sha256: 0xhex (for PCR 4 EV_EFI_BOOT_SERVICES_APPLICATION),
#   kernel_authcode_sha256: 0xhex (for PCR 4 EV_EFI_BOOT_SERVICES_APPLICATION),
#   initrd_plain_sha256: 0xhex (for PCR 9 EV_IPL),
#   kernel_cmdline: regex (for PCR 8 EV_IPL event.Event)
# }
# Here 0xhex is a string starting with '0x' and continuing with lowercase
# hex digits; in the case of a hash value, this includes leading zeros as
# needed to express the full number of bytes the hash function is defined
# to produce.
# A digest is a map from hash-algorithm-name (sha1 or sha256) to 0xhex.
# A key is {SignatureOwner: UUID, SignatureData: 0xhex}.

# First, define some helper functions for checking that the refstate is valid.
# They raise Exception when something invalid is encountered.

hex_pat = re.compile("0x[0-9a-f]+")


def hex_test(dat: typing.Any) -> bool:
    if isinstance(dat, str) and hex_pat.fullmatch(dat):
        return True
    raise Exception(f"{dat!r} is not 0x followed by some lowercase hex digits")


digest_type_test = tests.dict_test(tests.type_test(str), hex_test)

allowed_scrtm_and_bios_test = tests.obj_test(
    scrtm=digest_type_test, platform_firmware=tests.list_test(digest_type_test)
)

allowed_scrtm_and_bios_list_test = tests.list_test(allowed_scrtm_and_bios_test)

allowed_kernel_test = tests.obj_test(
    shim_authcode_sha256=hex_test,
    grub_authcode_sha256=hex_test,
    kernel_authcode_sha256=hex_test,
    initrd_plain_sha256=hex_test,
    kernel_cmdline=tests.type_test(str),
)

allowed_kernel_list_test = tests.list_test(allowed_kernel_test)

shim_authcode_sha256_no_secureboot = tests.obj_test(
    shim_authcode_sha256=hex_test,
    grub_authcode_sha256=hex_test,
    vmlinuz_plain_sha256=hex_test,
    initrd_plain_sha256=hex_test,
    kernel_cmdline=tests.type_test(str),
)


allowed_kernel_list_test_no_secureboot = tests.list_test(shim_authcode_sha256_no_secureboot)


class Example(policies.Policy):
    relevant_pcr_indices = frozenset(list(range(10)) + [14])

    def get_relevant_pcrs(self) -> typing.FrozenSet[int]:
        return self.relevant_pcr_indices

    def refstate_to_test(self, refstate: policies.RefState) -> tests.Test:
        """Return the boot event log test corresponding to the given refstate
        The given refstate is expected to be Python data coming from `json.load`"""
        if not isinstance(refstate, dict):
            raise Exception(f"Expected refstate to be a Python dict but instead got this Python value: {refstate!r}")

        has_secureboot = refstate.get("has_secureboot", True)

        kernels = refstate.get("kernels")
        if not isinstance(kernels, list):
            raise Exception(f"refstate['kernels'] is {kernels!r} instead of a list")
        if has_secureboot:
            allowed_kernel_list_test(kernels)
        else:
            allowed_kernel_list_test_no_secureboot(kernels)

        scrtm_and_bios_spec = refstate.get("scrtm_and_bios")
        if scrtm_and_bios_spec is None:
            raise Exception("refstate['scrtm_and_bios'] is missing")
        allowed_scrtm_and_bios_list_test(scrtm_and_bios_spec)
        scrtm_and_bios_test = tests.Or(
            *[
                tests.And(
                    tests.FieldTest("s_crtms", tests.TupleTest(tests.DigestTest(digest_strip0x(allowed["scrtm"])))),
                    tests.FieldTest(
                        "platform_firmware_blobs",
                        tests.TupleTest(*[tests.DigestTest(digest_strip0x(pf)) for pf in allowed["platform_firmware"]]),
                    ),
                )
                for allowed in scrtm_and_bios_spec
            ]
        )

        for req in ("pk", "kek", "db", "dbx", "mokdig", "mokxdig"):
            if req not in refstate:
                raise Exception(f"refstate lacks {req}")

        dispatcher = tests.Dispatcher(("PCRIndex", "EventType"))
        vd_driver_config = tests.VariableDispatch()
        vd_authority = tests.VariableDispatch()

        def bsa_test(kernel: typing.Dict[str, str]) -> tests.Test:
            if not has_secureboot:
                # When SecureBoot is disabled, GRUB does not use SHIM_LOCK to verify the signature therefore
                # there is no EV_EFI_BOOT_SERVICES_APPLICATION entry.
                tt = [
                    tests.DigestTest({"sha256": string_strip0x(kernel["shim_authcode_sha256"])}),
                    tests.DigestTest({"sha256": string_strip0x(kernel["grub_authcode_sha256"])}),
                ]
                return tests.TupleTest(*tt)

            tt = [
                tests.DigestTest({"sha256": string_strip0x(kernel["shim_authcode_sha256"])}),
                tests.DigestTest({"sha256": string_strip0x(kernel["grub_authcode_sha256"])}),
                tests.DigestTest({"sha256": string_strip0x(kernel["kernel_authcode_sha256"])}),
            ]
            # In some scenarios the kernel gets measured twice
            tt2 = [
                tests.DigestTest({"sha256": string_strip0x(kernel["shim_authcode_sha256"])}),
                tests.DigestTest({"sha256": string_strip0x(kernel["grub_authcode_sha256"])}),
                tests.DigestTest({"sha256": string_strip0x(kernel["kernel_authcode_sha256"])}),
                tests.DigestTest({"sha256": string_strip0x(kernel["kernel_authcode_sha256"])}),
            ]
            return tests.Or(tests.TupleTest(*tt), tests.TupleTest(*tt2))

        def vmlinuz_test(kernel: typing.Dict[str, str]) -> tests.Test:
            # Only when SecureBoot is disabled validate the vmlinuz digest measured by GRUB. When SecureBoot is enabled
            # this was already done using the tests for EV_EFI_BOOT_SERVICES_APPLICATION.
            if has_secureboot:
                return tests.AcceptAll()
            return tests.DigestTest({"sha256": string_strip0x(kernel["vmlinuz_plain_sha256"])})

        events_final = tests.DelayToFields(
            tests.And(
                tests.Or(
                    *[
                        tests.FieldsTest(
                            bsas=bsa_test(kernel),
                            ipl9s=tests.TupleTest(
                                tests.DigestTest({"sha256": string_strip0x(kernel["initrd_plain_sha256"])})
                            ),
                            vmlinuz=tests.TupleTest(vmlinuz_test(kernel)),
                            kernel_cmdlines=tests.TupleTest(
                                tests.RegExp("kernel_cmdline: " + kernel["kernel_cmdline"])
                            ),
                        )
                        for kernel in kernels
                    ]
                ),
                scrtm_and_bios_test,
            ),
            "kernel_cmdlines",
            "bsas",
            "ipl9s",
            "vmlinuz",
            "s_crtms",
            "platform_firmware_blobs",
        )
        # We only expect one EV_NO_ACTION event at the start.
        dispatcher.set((0, "EV_NO_ACTION"), tests.OnceTest(tests.AcceptAll()))
        dispatcher.set((0, "EV_S_CRTM_VERSION"), events_final.get("s_crtms"))
        dispatcher.set((0, "EV_EFI_PLATFORM_FIRMWARE_BLOB"), events_final.get("platform_firmware_blobs"))
        dispatcher.set((7, "EV_EFI_VARIABLE_DRIVER_CONFIG"), vd_driver_config)
        secure_boot_test = tests.FieldTest("Enabled", tests.StringEqual("Yes"))
        if not has_secureboot:
            secure_boot_test = tests.FieldTest("Enabled", tests.StringEqual("No"))
        # tpm2-tools versions < 5.2 parsed the GUIDs wrong therefore we include a check for both here
        # For more information see: https://github.com/keylime/keylime/issues/1003
        vd_driver_config.set("61dfe48b-ca93-d211-aa0d-00e098032b8c", "SecureBoot", secure_boot_test)
        vd_driver_config.set("8be4df61-93ca-11d2-aa0d-00e098032b8c", "SecureBoot", secure_boot_test)
        pk_test = tests.OnceTest(
            tests.Or(
                tests.KeySubset("a159c0a5-e494-a74a-87b5-ab155c2bf072", sigs_strip0x(refstate["pk"])),
                tests.KeySubset("a5c059a1-94e4-4aa7-87b5-ab155c2bf072", sigs_strip0x(refstate["pk"])),
            )
        )
        vd_driver_config.set(
            "61dfe48b-ca93-d211-aa0d-00e098032b8c",
            "PK",
            pk_test,
        )
        vd_driver_config.set(
            "8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "PK",
            pk_test,
        )

        kek_test = tests.OnceTest(
            tests.Or(
                tests.KeySubset("a159c0a5-e494-a74a-87b5-ab155c2bf072", sigs_strip0x(refstate["kek"])),
                tests.KeySubset("a5c059a1-94e4-4aa7-87b5-ab155c2bf072", sigs_strip0x(refstate["kek"])),
            )
        )
        vd_driver_config.set(
            "61dfe48b-ca93-d211-aa0d-00e098032b8c",
            "KEK",
            kek_test,
        )
        vd_driver_config.set(
            "8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "KEK",
            kek_test,
        )
        db_test = tests.OnceTest(
            tests.Or(
                tests.KeySubset("a159c0a5-e494-a74a-87b5-ab155c2bf072", sigs_strip0x(refstate["db"])),
                tests.KeySubset("a5c059a1-94e4-4aa7-87b5-ab155c2bf072", sigs_strip0x(refstate["db"])),
            )
        )
        vd_driver_config.set(
            "cbb219d7-3a3d-9645-a3bc-dad00e67656f",
            "db",
            db_test,
        )
        vd_driver_config.set(
            "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
            "db",
            db_test,
        )
        dbx_test = tests.OnceTest(
            tests.Or(
                tests.KeySuperset("2616c4c1-4c50-9240-aca9-41f936934328", sigs_strip0x(refstate["dbx"])),
                tests.KeySuperset("c1c41626-504c-4092-aca9-41f936934328", sigs_strip0x(refstate["dbx"])),
            )
        )
        vd_driver_config.set(
            "cbb219d7-3a3d-9645-a3bc-dad00e67656f",
            "dbx",
            dbx_test,
        )
        vd_driver_config.set(
            "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
            "dbx",
            dbx_test,
        )
        dispatcher.set((7, "EV_EFI_VARIABLE_AUTHORITY"), vd_authority)
        # Assume that the cert that was used to verify the Shim is always trusted.
        # TODO: can we use the db entry for that instead of AcceptAll?
        vd_db_test = tests.OnceTest(tests.AcceptAll())
        vd_authority.set("cbb219d7-3a3d-9645-a3bc-dad00e67656f", "db", vd_db_test)
        vd_authority.set("d719b2cb-3d3a-4596-a3bc-dad00e67656f", "db", vd_db_test)
        # Accept all SbatLevels of the Shim, because we already checked the hash of the Shim itself.
        vd_sbat_level_test = tests.OnceTest(tests.AcceptAll())
        vd_authority.set("50ab5d60-46e0-0043-abb6-3dd810dd8b23", "SbatLevel", vd_sbat_level_test)
        vd_authority.set("605dab50-e046-4300-abb6-3dd810dd8b23", "SbatLevel", vd_sbat_level_test)
        # Accept all certificates that are used by the Shim to verify the next component,
        # because we already checked the hash of the Shim itself.
        vd_shim_test = tests.OnceTest(tests.AcceptAll())
        vd_authority.set("50ab5d60-46e0-0043-abb6-3dd810dd8b23", "Shim", vd_shim_test)
        vd_authority.set("605dab50-e046-4300-abb6-3dd810dd8b23", "Shim", vd_shim_test)
        # Because we validate the MokList, we do not check if the kernel should trust those keys.
        vd_authority.set(
            "605dab50-e046-4300-abb6-3dd810dd8b23",
            "MokListTrusted",
            tests.OnceTest(
                tests.Or(
                    tests.FieldTest("Enabled", tests.StringEqual("Yes")),
                    tests.FieldTest("Enabled", tests.StringEqual("No")),
                )
            ),
        )

        # A list of allowed digests for firmware from device driver appears
        # in PCR2, event type EV_EFI_BOOT_SERVICES_DRIVER. Here we will just
        # accept everything.
        # This is fine because we do not use any other entry type from PCR 2 for validation.
        dispatcher.set((2, "EV_EFI_BOOT_SERVICES_DRIVER"), tests.AcceptAll())
        dispatcher.set(
            (1, "EV_EFI_VARIABLE_BOOT"),
            tests.Or(
                tests.VariableTest(
                    "61dfe48b-ca93-d211-aa0d-00e098032b8c", re.compile("BootOrder|Boot[0-9a-fA-F]+"), tests.AcceptAll()
                ),
                tests.VariableTest(
                    "8be4df61-93ca-11d2-aa0d-00e098032b8c", re.compile("BootOrder|Boot[0-9a-fA-F]+"), tests.AcceptAll()
                ),
            ),
        )
        dispatcher.set((4, "EV_EFI_ACTION"), tests.EvEfiActionTest(4))
        for pcr in range(8):
            dispatcher.set((pcr, "EV_SEPARATOR"), tests.EvSeperatorTest())

        dispatcher.set((4, "EV_EFI_BOOT_SERVICES_APPLICATION"), events_final.get("bsas"))
        dispatcher.set(
            (14, "EV_IPL"),
            tests.Or(
                tests.And(
                    tests.FieldTest("Event", tests.FieldTest("String", tests.StringEqual("MokList"))),
                    tests.DigestsTest(digests_strip0x(refstate["mokdig"])),
                ),
                tests.And(
                    tests.FieldTest("Event", tests.FieldTest("String", tests.StringEqual("MokListX"))),
                    tests.DigestsTest(digests_strip0x(refstate["mokxdig"])),
                ),
                tests.And(
                    tests.FieldTest("Event", tests.FieldTest("String", tests.StringEqual("MokListTrusted"))),
                    tests.OnceTest(tests.AcceptAll()),
                ),
            ),
        )
        dispatcher.set(
            (9, "EV_IPL"),
            tests.Or(
                tests.FieldTest(
                    "Event", tests.FieldTest("String", tests.RegExp(r".*/loader/entries.*"))
                ),  # Ignore  Boot Loader Spec files
                tests.FieldTest("Event", tests.FieldTest("String", tests.RegExp(r".*/grub.*"))),
                tests.And(
                    tests.FieldTest("Event", tests.FieldTest("String", tests.RegExp(r".*/vmlinuz.*"))),
                    events_final.get("vmlinuz"),  # Note: this evaluates always to true if SecureBoot is enabled
                ),
                tests.And(
                    tests.FieldTest(
                        "Event",
                        tests.FieldTest(
                            "String",
                            tests.Or(
                                tests.RegExp(r".*/initrd.*"),
                                tests.RegExp(r".*/initramfs.*"),
                            ),
                        ),
                    ),
                    events_final.get("ipl9s"),
                ),
            ),
        )
        dispatcher.set(
            (8, "EV_IPL"),
            tests.FieldTest(
                "Event",
                tests.FieldTest(
                    "String",
                    tests.Or(
                        tests.RegExp("grub_cmd: .*", re.DOTALL),
                        tests.And(tests.RegExp("kernel_cmdline: .*"), events_final.get("kernel_cmdlines")),
                    ),
                ),
            ),
        )
        dispatcher.set((5, "EV_EFI_ACTION"), tests.EvEfiActionTest(5))
        # Accept all UEFI_GPT_DATA. We only expect one entry for that.
        dispatcher.set((5, "EV_EFI_GPT_EVENT"), tests.OnceTest(tests.AcceptAll()))
        events_test = tests.FieldTest(
            "events",
            tests.And(events_final.get_initializer(), tests.IterateTest(dispatcher, show_elt=True), events_final),
            show_name=False,
        )
        return events_test


def string_strip0x(con: str) -> str:
    if con.startswith("0x"):
        return con[2:]
    raise Exception(f"{con!r} does not start with 0x")


def digest_strip0x(digest: typing.Dict[str, str]) -> tests.Digest:
    digest_type_test(digest)
    return {alg: string_strip0x(val) for alg, val in digest.items()}


def digests_strip0x(digests: typing.List[typing.Dict[str, str]]) -> typing.List[tests.Digest]:
    tests.type_test(list)(digests)
    return list(map(digest_strip0x, digests))


def sig_strip0x(sig: typing.Dict[str, str]) -> tests.Signature:
    tests.obj_test(SignatureOwner=tests.type_test(str), SignatureData=tests.type_test(str))(sig)
    return dict(SignatureOwner=sig["SignatureOwner"], SignatureData=string_strip0x(sig["SignatureData"]))


def sigs_strip0x(sigs: typing.Iterable[typing.Dict[str, str]]) -> typing.List[tests.Signature]:
    tests.type_test(typing.Iterable)(sigs)
    return list(map(sig_strip0x, sigs))


policies.register("example", Example())
