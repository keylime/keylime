"""
Module to generate a valid measured boot policy.

Copyright 2021 Thore Sommer
"""

import argparse
import json
import re
import sys
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from keylime.mba.elparsing.tpm2_tools_elparser import parse_binary_bootlog
from keylime.policy.logger import Logger

if TYPE_CHECKING:
    # FIXME: how to make mypy and pylint happy here?
    _SubparserType = argparse._SubParsersAction[argparse.ArgumentParser]  # pylint: disable=protected-access
else:
    _SubparserType = Any

logger = Logger().logger()


def event_to_sha256(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the sha256 digest from an event."""
    for digest in event["Digests"]:
        if digest["AlgorithmId"] == "sha256":
            return {"sha256": f"0x{digest['Digest']}"}
    return {}


def get_s_crtm(events: List[Dict[Any, str]]) -> Dict[str, Any]:
    """Find the EV_S_CRTM_VERSION."""
    for event in events:
        if event["EventType"] == "EV_S_CRTM_VERSION":
            return {"scrtm": event_to_sha256(event)}
    return {}


def get_platform_firmware(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Get all platform specific files measured with EV_EFI_PLATFORM_FIRMWARE_BLOB/EV_EFI_PLATFORM_FIRMWARE_BLOB2 events."""
    out = []
    for event in events:
        if event["EventType"] not in ["EV_EFI_PLATFORM_FIRMWARE_BLOB", "EV_EFI_PLATFORM_FIRMWARE_BLOB2"]:
            continue
        out.append(event_to_sha256(event))
    return {"platform_firmware": out}


def variabledata_to_signature(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert VariableData entry from EV_EFI_VARIABLE_DRIVER_CONFIG to signature data."""
    out = []
    for entry in data:
        for key in entry["Keys"]:
            out.append({"SignatureOwner": key["SignatureOwner"], "SignatureData": f"0x{key['SignatureData']}"})
    return out


def get_keys(events: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    """Get valid signatures for UEFI Secure Boot PK, KEK, DB and DBX."""
    out: Dict[str, List[Any]] = {"pk": [], "kek": [], "db": [], "dbx": []}
    for event in events:
        if event["EventType"] != "EV_EFI_VARIABLE_DRIVER_CONFIG":
            continue
        event_name = event["Event"]["UnicodeName"].lower()

        if event_name in out:
            data = event["Event"]["VariableData"]

            if data is not None:
                out[event_name] = variabledata_to_signature(data)
    return out


def get_kernel(events: List[Dict[str, Any]], secure_boot: bool) -> Dict[str, List[Dict[str, Any]]]:
    """Extract digest for Shim, Grub, Linux Kernel and initrd."""
    out = []

    # Some firmware implement the UEFI boot menu and other system components
    # as UEFI applications, and those are measured in the boot chain. As we
    # currently have no reference values for those, we will ignore them for
    # now.
    # Workaround from: https://github.com/Lernstick/Lernstick-Bridge/blob/6defec/measured_boot/lernstick_policy.py#L89

    uefi_app_pattern = re.compile(r"FvVol\(\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\)/FvFile\(\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\)")
    for event in events:
        if event["EventType"] != "EV_EFI_BOOT_SERVICES_APPLICATION":
            continue

        if uefi_app_pattern.match(event["Event"]["DevicePath"]):
            continue

        out.append(event_to_sha256(event))
    kernel = {"shim_authcode_sha256": out[0]["sha256"], "grub_authcode_sha256": out[1]["sha256"]}

    if secure_boot:
        assert len(out) in [3, 4], "Expected 3 different UEFI applications to be booted (Shim, Grub, Linux)"
        kernel["kernel_authcode_sha256"] = out[2]["sha256"]
    else:
        assert len(out) == 2, "Expected 2 different UEFI applications to be booted (Shim, Grub)"

    for event in events:
        if event["EventType"] != "EV_IPL" or event["PCRIndex"] != 9:
            continue

        if "initrd" in event["Event"]["String"] or "initramfs" in event["Event"]["String"]:
            kernel["initrd_plain_sha256"] = event_to_sha256(event)["sha256"]
            break

    if not secure_boot:
        logger.info("Adding plain sha256 digest of vmlinuz for GRUB to reference state, because SecureBoot is disabled")

        for event in events:
            if event["EventType"] != "EV_IPL" or event["PCRIndex"] != 9:
                continue

            if "vmlinuz" in event["Event"]["String"]:
                kernel["vmlinuz_plain_sha256"] = event_to_sha256(event)["sha256"]
                break

    for event in events:
        if event["EventType"] != "EV_IPL" or event["PCRIndex"] != 8:
            continue

        if "kernel_cmdline" in event["Event"]["String"]:
            kernel["kernel_cmdline"] = re.escape(event["Event"]["String"][len("kernel_cmdline: ") :])
            break
    return {"kernels": [kernel]}


def get_mok(events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Extract digest for MokList and MokListX."""
    out: Dict[str, List[Dict[str, Any]]] = {"mokdig": [], "mokxdig": []}
    for event in events:
        if event["EventType"] != "EV_IPL":
            continue

        if event["Event"]["String"] == "MokList":
            out["mokdig"].append(event_to_sha256(event))
        elif event["Event"]["String"] == "MokListX":
            out["mokxdig"].append(event_to_sha256(event))
    return out


def secureboot_enabled(events: List[Dict[str, Any]]) -> bool:
    """Check if Secure Boot is enabled."""
    for event in events:
        if event["EventType"] == "EV_EFI_VARIABLE_DRIVER_CONFIG" and event["Event"].get("UnicodeName") == "SecureBoot":
            ret: bool = event["Event"]["VariableData"]["Enabled"] == "Yes"
            return ret

    raise Exception("SecureBoot state could not be determined")


def get_arg_parser(create_parser: _SubparserType, parent_parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Perform the setup of the command-line arguments for this module."""
    mbref_p = create_parser.add_parser(
        "measured-boot", help="create measured boot reference state policy", parents=[parent_parser]
    )

    mbref_p.add_argument(
        "-e",
        "--eventlog-file",
        type=argparse.FileType("rb"),
        default=sys.stdin,
        required=True,
        help="Binary UEFI eventlog (Normally /sys/kernel/security/tpm0/binary_bios_measurements)",
    )
    mbref_p.add_argument(
        "--without-secureboot",
        "-i",
        action="store_true",
        help="Set if you want to create a measured boot reference state policy without SecureBoot (only MeasuredBoot)",
    )
    mbref_p.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help="Output path for the generated measured boot policy",
    )

    mbref_p.set_defaults(func=create_mb_refstate)
    return mbref_p


def create_mb_refstate(args: argparse.Namespace) -> Optional[Dict[str, object]]:
    """Create a measured boot reference state."""
    log_bin = args.eventlog_file.read()

    failure, log_data = parse_binary_bootlog(log_bin)
    if failure or not log_data:
        logger.error(
            "Parsing of binary boot measurements failed with: %s", list(map(lambda x: x.context, failure.events))
        )
        return None

    events = log_data.get("events")
    if not events:
        logger.error("No events found on binary boot measurements log")
        return None

    has_secureboot = secureboot_enabled(events)
    if not has_secureboot and not args.without_secureboot:
        logger.error("Provided eventlog has SecureBoot disabled, but -i flag was not set")
        return None

    if has_secureboot and args.without_secureboot:
        logger.warning(
            "-i/--without-secureboot was set to create a reference state without SecureBoot, "
            "but the provided eventlog has SecureBoot enabled. Ignoring this flag"
        )

    mb_refstate = {
        "has_secureboot": has_secureboot,
        "scrtm_and_bios": [
            {
                **get_s_crtm(events),
                **get_platform_firmware(events),
            }
        ],
        **get_keys(events),
        **get_mok(events),
        **get_kernel(events, has_secureboot),
    }
    json.dump(mb_refstate, args.output)
    return mb_refstate
