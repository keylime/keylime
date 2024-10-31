"""
Module to assist with creating runtime policies.
"""

import enum
from typing import IO, Any, Dict, List, Optional


def merge_lists(list1: List[Any], list2: List[Any]) -> List[Any]:
    """Merge two lists removing repeated entries."""
    list1.extend(list2)
    return sorted(list(set(list1)))


def merge_maplists(map1: Dict[Any, List[Any]], map2: Dict[Any, List[Any]]) -> Dict[Any, List[Any]]:
    """Merge two maps of lists, removing repeated entries in the lists."""
    for key, value in map2.items():
        if key not in map1:
            map1[key] = value
            continue
        map1[key] = merge_lists(map1[key], map2[key])
    return map1


def read_bytes_from_open_file(infile: IO[bytes], offset: int, count: int) -> bytes:
    """
    Read a specified amount of bytes from the input file, from a given offset.

    :param infile: the (open) file to read the files from
    :param offset: the offset to use with the provided file to read the bytes from
    :param count: the amount of bytes to read from
    :return: the requested bytes
    """
    infile.seek(offset)
    return infile.read(count)


def read_bytes_from_file(fpath: str, offset: int, count: int) -> bytes:
    """
    Read a specified amount of bytes from the input file, from a given offset.

    :param fpath: the path for the file to read the bytes from
    :param offset: the offset to use with the provided file to read the bytes from
    :param count: the amount of bytes to read from
    :return: the requested bytes
    """
    with open(fpath, "rb") as infile:
        return read_bytes_from_open_file(infile, offset, count)


class Magic(bytes, enum.Enum):
    """Magic bytes for identifying file types."""

    CPIO_NEW_ASCII = b"070701"
    CPIO_CRC = b"070702"
    LZO = b"\x89\x4c\x5a\x4f\x00\x0d"
    BZIP2 = b"BZh"
    GZIP = b"\x1f\x8b"
    ZSTD = b"\x28\xB5\x2F\xFD"
    LZ4 = b"\x04\x22\x4d\x18"
    XZ = b"\xFD\x37\x7A\x58\x5A\x00"


class Compression(str, enum.Enum):
    """Compression formats."""

    BZIP2 = "bzip2"
    GZIP = "gzip"
    ZSTD = "zstd"
    XZ = "xz"
    LZO = "lzo"
    LZ4 = "lz4"
    ZCK = "zchunk"
    CPIO = "cpio"

    @staticmethod
    def detect(magic: bytes) -> Optional[str]:
        """Detect compression format from given magic bytes."""
        # Magic bytes for identifying file types.
        MAGIC_CPIO_NEW_ASCII: bytes = b"070701"
        MAGIC_CPIO_CRC: bytes = b"070702"
        MAGIC_LZO: bytes = b"\x89\x4c\x5a\x4f\x00\x0d"
        MAGIC_BZIP2: bytes = b"BZh"
        MAGIC_GZIP: bytes = b"\x1f\x8b"
        MAGIC_ZSTD: bytes = b"\x28\xB5\x2F\xFD"
        MAGIC_LZ4: bytes = b"\x04\x22\x4d\x18"
        MAGIC_XZ: bytes = b"\xFD\x37\x7A\x58\x5A\x00"
        MAGIC_ZCK_V1: bytes = b"\x00ZCK1"
        MAGIC_ZCK_DET_V1: bytes = b"\x00ZHR1"

        formats = {
            MAGIC_CPIO_NEW_ASCII: Compression.CPIO,
            MAGIC_CPIO_CRC: Compression.CPIO,
            MAGIC_LZO: Compression.LZO,
            MAGIC_BZIP2: Compression.BZIP2,
            MAGIC_GZIP: Compression.GZIP,
            MAGIC_ZSTD: Compression.ZSTD,
            MAGIC_LZ4: Compression.LZ4,
            MAGIC_XZ: Compression.XZ,
            MAGIC_ZCK_V1: Compression.ZCK,
            MAGIC_ZCK_DET_V1: Compression.ZCK,
        }

        for m, ctype in formats.items():
            if magic.startswith(m):
                return ctype

        return None

    @staticmethod
    def detect_from_open_file(infile: IO[bytes], offset: int = 0) -> Optional[str]:
        """Detect compression format from given file and offset."""
        _MAGIC_LEN = 6
        magic = read_bytes_from_open_file(infile, offset, _MAGIC_LEN)
        return Compression.detect(magic)

    @staticmethod
    def detect_from_file(fpath: str, offset: int = 0) -> Optional[str]:
        """Detect compression format from given file path and offset."""
        with open(fpath, "rb") as infile:
            return Compression.detect_from_open_file(infile, offset)
