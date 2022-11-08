# important notice: this file was temporarly added to keylime in order to cover the gap
# left by some additiomal features still not available on Intel's tpm2-tools. There is
# an ongoing effort to add the aforementioned features to their toolkit and when this
# process is complete this file will become redundant and ready for removal.

import argparse
import json
import re
import sys
import traceback
from ctypes import CDLL, byref, c_char_p, create_string_buffer

import yaml

try:
    from yaml import CSafeLoader as SafeLoader
except ImportError:
    from yaml import SafeLoader

from keylime import config

##################################################################################
#
# yaml by default outputs numbers in decimal format, and this allows us to
# represent some numbers in hexadecimal
#
##################################################################################


class hexint(int):
    pass


def representer(_, data):
    return yaml.ScalarNode("tag:yaml.org,2002:int", hex(data))


yaml.add_representer(hexint, representer)

##################################################################################
#
# These function use efivar C libraries to decode device path and guid
#
##################################################################################

efivarlib_functions = CDLL(config.LIBEFIVAR)


def getDevicePath(b, l):
    ret = efivarlib_functions.efidp_format_device_path(0, 0, b, l)
    if ret < 0:
        raise Exception(f"getDevicePath: efidp_format_device_path({b}) returned {ret}")

    s = create_string_buffer(ret + 1)

    ret = efivarlib_functions.efidp_format_device_path(s, ret + 1, b, l)
    if ret < 0:
        raise Exception(f"getDevicePath: efidp_format_device_path({b}) returned {ret}")

    return s.value.decode("utf-8")


def getGUID(b):
    s = c_char_p(None)
    ret = efivarlib_functions.efi_guid_to_str(b, byref(s))
    if ret < 0:
        raise Exception(f"getGUID: efi_guid_to_str({b}) returned {ret}")
    assert isinstance(s.value, bytes)
    return s.value.decode("utf-8")  # pylint: disable=E1101


##################################################################################
#
# https://uefi.org/sites/default/files/resources/UEFI%20Spec%202.8B%20May%202020.pdf
# Section 32.4.1
#
# Relevant data structures
#
#  typedef struct _EFI_SIGNATURE_LIST {
#       uint8_t SignatureType[16];
#       uint32_t SignatureListSize;
#       uint32_t SignatureHeaderSize;
#       uint32_t SignatureSize;
#       // uint8_t SignatureHeader[SignatureHeaderSize];
#       // uint8_t Signatures[][SignatureSize];
#  } EFI_SIGNATURE_LIST;
#
#  typedef struct _EFI_SIGNATURE_DATA {
#      uint8_t SignatureOwner[16];
#      uint8_t SignatureData[];
#  } EFI_SIGNATURE_DATA;
#
##################################################################################

##################################################################################
# Parse EFI_SIGNATURE_DATA
##################################################################################


def getKey(b, start, size):
    key = {}
    signatureOwner = getGUID(b[start : start + 16])
    key["SignatureOwner"] = signatureOwner

    signatureData = b[start + 16 : start + size]
    key["SignatureData"] = signatureData.hex()
    return key


##################################################################################
#
# https://uefi.org/sites/default/files/resources/UEFI%20Spec%202.8B%20May%202020.pdf
# Section 3.1.3
#
# Relevant data structures
#
#   typedef struct _EFI_LOAD_OPTION {
#       UINT32 Attributes;
#       UINT16 FilePathListLength;
#       // CHAR16 Description[];
#       // EFI_DEVICE_PATH_PROTOCOL FilePathList[];
#       // UINT8 OptionalData[];} EFI_LOAD_OPTION;
#   } EFI_LOAD_OPTION;
#
##################################################################################

##################################################################################
# Parse additional information about variables BootOrder and Boot####
##################################################################################


def getVar(event, b):
    if "UnicodeName" in event:
        if "VariableDataLength" in event:
            varlen = event["VariableDataLength"]

            # BootOrder variable
            if event["UnicodeName"] == "BootOrder":
                if varlen % 2 != 0:
                    raise Exception(f"getVar: VariableDataLength({varlen}) is not divisible by 2")

                l = int(varlen / 2)
                r = []
                for x in range(l):
                    d = int.from_bytes(b[x * 2 : x * 2 + 2], byteorder="little")
                    r.append(f"Boot{d:04x}")
                return r
            # Boot#### variable
            if re.match("Boot[0-9a-fA-F]{4}", event["UnicodeName"]):
                r = {}
                i = 0
                size = 4
                attributes = b[i : i + size]
                d = int.from_bytes(attributes, "little") & 1
                if d == 0:
                    r["Enabled"] = "No"
                else:
                    r["Enabled"] = "Yes"

                i += size
                size = 2
                filePathListLength = b[i : i + size]
                d = int.from_bytes(filePathListLength, "little")
                r["FilePathListLength"] = d

                i += size
                size = 2
                description = ""
                while i < varlen:
                    w = b[i : i + size]
                    i += size
                    if w == b"\x00\x00":
                        break

                    c = w.decode("utf-16", errors="ignore")
                    description += c
                r["Description"] = description
                devicePath = getDevicePath(b[i:], len(b[i:]))
                r["DevicePath"] = devicePath
                return r
    return None


def enrich_device_path(d: dict) -> None:
    if isinstance(d.get("DevicePath"), str):
        try:
            b = bytes.fromhex(d["DevicePath"])
            l = int(d["LengthOfDevicePath"])
        except Exception:
            return
        try:
            p = getDevicePath(b, l)
        # Deal with garbage devicePath
        except Exception:
            return
        d["DevicePath"] = p


def enrich_boot_variable(d: dict) -> None:
    if isinstance(d.get("VariableData"), str):
        b = {}
        b = bytes.fromhex(d["VariableData"])
        k = getVar(d, b)
        if k is not None:
            d["VariableData"] = k


def enrich(log: dict) -> None:
    """Make the given BIOS boot log easier to understand and process"""
    if "events" in log:
        events = log["events"]

        for event in events:
            if "EventType" in event:
                t = event["EventType"]
                if t in (
                    "EV_EFI_BOOT_SERVICES_APPLICATION",
                    "EV_EFI_BOOT_SERVICES_DRIVER",
                    "EV_EFI_RUNTIME_SERVICES_DRIVER",
                ):
                    if "Event" in event:
                        d = event["Event"]
                        enrich_device_path(d)
                elif t == "EV_EFI_VARIABLE_BOOT":
                    if "Event" in event:
                        d = event["Event"]
                        enrich_boot_variable(d)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", nargs="?", type=argparse.FileType("r"), default=sys.stdin)
    parser.add_argument("-o", "--output", choices=("yaml", "json"), default="yaml")
    args = parser.parse_args()
    log = yaml.load(args.infile, Loader=SafeLoader)
    try:
        enrich(log)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    if args.output == "yaml":
        print(yaml.dump(log, default_flow_style=False, line_break=None))
    elif args.output == "json":
        print(json.dumps(log, sort_keys=True, indent=4))
    else:
        raise Exception(f"unexpected output format {args.output!a}")


if __name__ == "__main__":
    main()
