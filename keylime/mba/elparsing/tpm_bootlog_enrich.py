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
from typing import Any, Dict

import yaml

from keylime import config

##################################################################################
#
# yaml by default outputs numbers in decimal format, and this allows us to
# represent some numbers in hexadecimal
#
##################################################################################


class HexInt(int):
    pass


def representer(_: Any, data: int) -> yaml.ScalarNode:
    return yaml.ScalarNode("tag:yaml.org,2002:int", hex(data))


yaml.add_representer(HexInt, representer)

##################################################################################
#
# These function use efivar C libraries to decode device path and guid
#
##################################################################################

efivarlib_functions = CDLL(config.LIBEFIVAR)


def getDevicePath(b: bytes, l: int) -> str:
    ret = efivarlib_functions.efidp_format_device_path(0, 0, b, l)
    if ret < 0:
        raise Exception(f"getDevicePath: efidp_format_device_path({str(b)}) returned {ret}")

    s = create_string_buffer(ret + 1)

    ret = efivarlib_functions.efidp_format_device_path(s, ret + 1, b, l)
    if ret < 0:
        raise Exception(f"getDevicePath: efidp_format_device_path({str(b)}) returned {ret}")

    return s.value.decode("utf-8")


def getGUID(b: bytes) -> str:
    s = c_char_p(None)
    ret = efivarlib_functions.efi_guid_to_str(b, byref(s))
    if ret < 0:
        raise Exception(f"getGUID: efi_guid_to_str({str(b)}) returned {ret}")
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

EFI_SIGNATURE_OWNER_SIZE = 16  # Size of SignatureOwner field (GUID).

# DER (Distinguished Encoding Rules) ASN.1 constants for X.509 certificate parsing.
# X.509 certificates start with: 0x30 0x82 [length-high] [length-low] [certificate-data...]
# where 0x30 = SEQUENCE tag, 0x82 = long form length encoding (next 2 bytes = length).
DER_SEQUENCE_TAG = 0x30  # ASN.1 SEQUENCE tag.
DER_LONG_LENGTH_FORM = 0x82  # Long form length encoding (2 bytes follow).
DER_TAG_BYTES = 2  # Bytes needed to check tag + length form (0x30 0x82).
DER_LENGTH_BYTES = 2  # Length field size in long form encoding.
DER_HEADER_SIZE = 4  # Total DER header size (tag + length-form + 2-byte length).
MAX_HEADER_SEARCH_BYTES = 100  # Maximum bytes to search for DER certificate start after GUID.

##################################################################################
# Parse EFI_SIGNATURE_DATA
##################################################################################


def getKey(b: bytes, start: int, size: int) -> Dict[str, Any]:
    key = {}
    signatureOwner = getGUID(b[start : start + EFI_SIGNATURE_OWNER_SIZE])
    key["SignatureOwner"] = signatureOwner

    signatureData = b[start + EFI_SIGNATURE_OWNER_SIZE : start + size]
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


def getVar(event: Dict[str, Any], b: bytes) -> Any:
    if "UnicodeName" in event:
        if "VariableDataLength" in event:
            varlen = event["VariableDataLength"]

            # BootOrder variable
            if event["UnicodeName"] == "BootOrder":
                if varlen % 2 != 0:
                    raise Exception(f"getVar: VariableDataLength({varlen}) is not divisible by 2")

                l = int(varlen / 2)
                r1 = []
                for x in range(l):
                    d = int.from_bytes(b[x * 2 : x * 2 + 2], byteorder="little")
                    r1.append(f"Boot{d:04x}")
                return r1
            # Boot#### variable
            if re.match("Boot[0-9a-fA-F]{4}", event["UnicodeName"]):
                r2 = {}
                i = 0
                size = 4
                attributes = b[i : i + size]
                d = int.from_bytes(attributes, "little") & 1
                if d == 0:
                    r2["Enabled"] = "No"
                else:
                    r2["Enabled"] = "Yes"

                i += size
                size = 2
                filePathListLength = b[i : i + size]
                d = int.from_bytes(filePathListLength, "little")
                r2["FilePathListLength"] = str(d)

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
                r2["Description"] = description
                devicePath = getDevicePath(b[i:], len(b[i:]))
                r2["DevicePath"] = devicePath
                return r2
    return None


def enrich_device_path(d: Dict[str, Any]) -> None:
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


def enrich_boot_variable(d: Dict[str, Any]) -> None:
    if isinstance(d.get("VariableData"), str):
        b = bytes.fromhex(d["VariableData"])
        k = getVar(d, b)
        if k is not None:
            d["VariableData"] = k


def enrich_vendor_db_authority_variable(d: Dict[str, Any]) -> None:
    """Normalize vendor_db in EV_EFI_VARIABLE_AUTHORITY events to signature list format.

    Different versions of tmp2_eventlog may provide vendor_db data in different formats:
    - Some versions output hex strings containing raw signature data (GUID + certificate data)
    - Other versions output parsed signature lists

    This function ensures we always end up with a list of signatures, regardless of
    how tpm2_eventlog provided the data.
    """
    # We are only interested in the vendor_db variable, and when it is an hex string.
    if d.get("UnicodeName") != "vendor_db":
        return

    if not isinstance(d.get("VariableData"), str):
        return

    try:
        b = bytes.fromhex(d["VariableData"])
        signatures = []

        offset = 0
        while offset < len(b):
            if offset + EFI_SIGNATURE_OWNER_SIZE >= len(b):
                break

            # Extract GUID at current offset.
            guid_bytes = b[offset : offset + EFI_SIGNATURE_OWNER_SIZE]
            guid = getGUID(guid_bytes)

            # Look for DER certificate signature (SEQUENCE + long form length) after some header data.
            cert_start = None
            search_end = min(offset + EFI_SIGNATURE_OWNER_SIZE + MAX_HEADER_SEARCH_BYTES, len(b) - DER_TAG_BYTES)
            for i in range(offset + EFI_SIGNATURE_OWNER_SIZE, search_end):
                if b[i] == DER_SEQUENCE_TAG and b[i + 1] == DER_LONG_LENGTH_FORM:
                    cert_start = i
                    break

            if cert_start is None:
                break

            # Parse DER certificate length.
            if cert_start + DER_HEADER_SIZE > len(b):
                break

            cert_length_bytes = b[cert_start + DER_TAG_BYTES : cert_start + DER_HEADER_SIZE]
            cert_length = (cert_length_bytes[0] << 8) | cert_length_bytes[1]
            cert_end = cert_start + DER_HEADER_SIZE + cert_length

            if cert_end > len(b):
                break

            # Extract certificate data (from GUID start to end of certificate).
            sig_data = b[offset + EFI_SIGNATURE_OWNER_SIZE : cert_end]

            signatures.append({"SignatureOwner": guid, "SignatureData": sig_data.hex()})

            # Move to next signature.
            offset = cert_end

        if signatures:
            d["VariableData"] = signatures
    except Exception:
        # If parsing fails, leave the hex string unchanged.
        pass


def enrich(log: Dict[str, Any]) -> None:
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
                elif t == "EV_EFI_VARIABLE_AUTHORITY":
                    if "Event" in event:
                        d = event["Event"]
                        enrich_vendor_db_authority_variable(d)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", nargs="?", type=argparse.FileType("r"), default=sys.stdin)
    parser.add_argument("-o", "--output", choices=("yaml", "json"), default="yaml")
    args = parser.parse_args()
    try:
        log = yaml.load(args.infile, Loader=yaml.CSafeLoader)
    except Exception:
        log = yaml.load(args.infile, Loader=yaml.SafeLoader)
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
