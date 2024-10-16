#!/usr/bin/env python3

"""
Module to help with extracting initrds.
"""

import os
import shutil
import subprocess
import tempfile
from importlib import util
from typing import IO, Dict

from keylime.policy.logger import Logger
from keylime.policy.utils import Compression, Magic, read_bytes_from_open_file

_HAS_LIBARCHIVE = util.find_spec("libarchive") is not None
if _HAS_LIBARCHIVE:
    import libarchive  # pylint: disable=import-error
else:
    libarchive = None

logger = Logger().logger()


class InitrdReader:
    """A helper class for reading the contents of an initrd. This is based on dracut's skipcpio."""

    _initrd_file: str = ""
    _contents_dir: str = ""
    _flist: Dict[str, str] = {}

    # New ASCII format. CRC format is identical, except that
    # the magic field is 070702 instead of 070701.
    # struct cpio_newc_header {
    #     char    c_magic[6];
    #     char    c_ino[8];
    #     char    c_mode[8];
    #     char    c_uid[8];
    #     char    c_gid[8];
    #     char    c_nlink[8];
    #     char    c_mtime[8];
    #     char    c_filesize[8];
    #     char    c_devmajor[8];
    #     char    c_devminor[8];
    #     char    c_rdevmajor[8];
    #     char    c_rdevminor[8];
    #     char    c_namesize[8];
    #     char    c_check[8];
    # }__attribute__((packed));

    # CPIO fields are 8 bytes long, except for the magic, which is 6.
    CPIO_MAGIC_LEN: int = 6
    CPIO_FIELD_LEN: int = 8
    CPIO_ALIGNMENT: int = 4
    CPIO_END: bytes = b"TRAILER!!!"
    CPIO_END_LEN: int = 10
    CPIO_NAMESIZE_OFFSET: int = 94  # 6 (magic) + 11 fields (x8)
    CPIO_FILESIZE_OFFSET: int = 54  # 6 (magic) + 6 fields (x8)
    CPIO_HEADER_LEN: int = 110  # 6 (magic) + 13 fields (x8)
    CPIO_HEADER_AND_TRAILING_LEN: int = CPIO_HEADER_LEN + CPIO_END_LEN

    @staticmethod
    def align_up(pos: int, alignment: int) -> int:
        """Align pos to the specified byte alignment."""
        return (pos + alignment - 1) & (~(alignment - 1))

    @staticmethod
    def extract_at_offset_fallback(infile: IO[bytes], offset: int) -> None:
        """
        Fall back for extracting an initrd at given offset.

        This method will extract an initrd by calling system programs
        to do the decompression and extraction, and will be used if
        libarchive is not available. Note that the data will be extracted
        at the current directory.

        :param infile: the (open) file we will be using to extract the data from
        :param offset: the offset in the provided file where the data to be extract starts
        :return: None
        """
        logger.debug("extract_at_offset_fallback(): file %s, offset %s", infile.name, offset)

        decompression: Dict[str, str] = {
            Compression.LZO: "lzop -d -c",
            Compression.BZIP2: "bzcat --",
            Compression.CPIO: "cat --",
            Compression.GZIP: "zcat --",
            Compression.ZSTD: "zstd -d -c",
            Compression.LZ4: "lz4 -d -c",
            Compression.XZ: "xzcat --",
        }

        # cat will be used for the decompression, and may be one of
        # the following programs: lzop, bzcat, zcat, zstd, lz4, xzcat
        # or even cat itself, if no compression is used.
        cat: str = decompression[Compression.XZ]
        comp_type = Compression.detect_from_open_file(infile, offset)
        if comp_type and comp_type in decompression:
            cat = decompression[comp_type]

        logger.debug("extract_at_offset_fallback(): identified format %s", cat)

        # We need 2 programs to do this, the one identified in the previous
        # step, to do the decompression, stored in the cat variable, plus
        # cpio itself. Let's check if we have them avialable before moving
        # ahead.

        cat_args = cat.split(" ")
        orig_cat_bin = cat_args[0]
        cat_bin = shutil.which(orig_cat_bin)
        if cat_bin is None:
            errmsg = f"Unable to move forward; '{orig_cat_bin}' not available in the path"
            logger.error(errmsg)
            raise Exception(errmsg)
        cat_args[0] = cat_bin

        cpio_bin = shutil.which("cpio")
        if cpio_bin is None:
            errmsg = "Unable to move forward; 'cpio' not available in the path"
            logger.error(errmsg)
            raise Exception(errmsg)
        cpio_args = f"{cpio_bin} --quiet -i".split(" ")

        # Ok, we have the required programs, so now we need to run cat,
        # to possibly decompress the data, then use its output and input
        # to cpio.
        infile.seek(offset)
        data = infile.read()

        with subprocess.Popen(
            cat_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as cat_proc:
            decompressed, stderr = cat_proc.communicate(input=data)
            if cat_proc.returncode != 0:
                errmsg = f"Unable to process file '{infile.name}' at offset {offset} with '{orig_cat_bin}': {stderr.decode('UTF-8')}"
                logger.error(errmsg)
                raise Exception(errmsg)
            with subprocess.Popen(cpio_args, stdin=subprocess.PIPE) as cpio_proc:
                _, stderr = cpio_proc.communicate(input=decompressed)
                if cpio_proc.returncode != 0:
                    errmsg = f"Unable to process cpio archive from file '{infile.name}' at offset {offset}: {stderr.decode('UTF-8')}"
                    logger.error(errmsg)
                    raise Exception(errmsg)

    @staticmethod
    def extract_at_offset_libarchive(infile: IO[bytes], offset: int) -> None:
        """
        libarchive-based initrd extractor.

        This method will extract an initrd using the libarchive module.
        Note that the data will be extracted at the current directory.

        :param infile: the (open) file we will be using to extract the data from
        :param offset: the offset in the provided file where the data to be extract starts
        :return: None
        """
        logger.debug("extract_at_offset_libarchive(): file %s, offset %s", infile.name, offset)

        if not _HAS_LIBARCHIVE or not libarchive:
            raise Exception("libarchive is not available")

        infile.seek(offset)
        data = infile.read()

        try:
            libarchive.extract_memory(data)
        except Exception as exc:
            errmsg = f"Unable to extract data from '{infile.name}' at offset {offset} with libarchive: {exc}"
            logger.error(errmsg)
            raise Exception(errmsg) from None

    @staticmethod
    def extract_at_offset(infile: IO[bytes], offset: int, dstdir: str) -> None:
        """
        Extract an initrd file from given offset to a given directory.

        This method extracts the contents of an initrd indicated by the the
        file and offset provided. It will either use libarchive, if available,
        or fall back to doing the extraction by using system commands.

        :param infile: the (open) file to use for getting the data
        :param offset: the offset in the provided file where the data start
        :param dstdir: the directory to extract the data at
        :return: None
        """
        prevdir = os.getcwd()

        extract_method = InitrdReader.extract_at_offset_fallback
        if _HAS_LIBARCHIVE:
            extract_method = InitrdReader.extract_at_offset_libarchive

        try:
            os.chdir(dstdir)
            extract_method(infile, offset)
        finally:
            os.chdir(prevdir)

    @staticmethod
    def is_eof(f: IO[bytes]) -> bool:
        """Check for EOF (enf of file)."""
        s = f.read(1)
        if s != b"":  # Restore position.
            f.seek(-1, os.SEEK_CUR)

        return s == b""

    @staticmethod
    def skip_cpio(infile: IO[bytes]) -> int:
        """
        Find the offset where the "main" initrd starts.

        :param infile: an open file handle for the initrd
        :return: int, the offset where the data of interest starts
        """
        pos = 0
        previous = 0
        parsing = False
        buffer_size: int = 2048  # Buffer arbitrarily long.
        cpio_formats = (Magic.CPIO_NEW_ASCII, Magic.CPIO_CRC)

        buffer = read_bytes_from_open_file(infile, pos, buffer_size)
        # Reset file offset.
        infile.seek(0)

        # Now let's check if it's a cpio archive.
        magic = buffer[: InitrdReader.CPIO_MAGIC_LEN]
        if magic not in cpio_formats:
            return pos

        while True:
            filename_len = int(
                "0x"
                + buffer[
                    InitrdReader.CPIO_NAMESIZE_OFFSET : InitrdReader.CPIO_NAMESIZE_OFFSET + InitrdReader.CPIO_FIELD_LEN
                ].decode("UTF-8"),
                0,
            )
            filesize = int(
                "0x"
                + buffer[
                    InitrdReader.CPIO_FILESIZE_OFFSET : InitrdReader.CPIO_FILESIZE_OFFSET + InitrdReader.CPIO_FIELD_LEN
                ].decode("UTF-8"),
                0,
            )

            filename = buffer[InitrdReader.CPIO_HEADER_LEN : pos + InitrdReader.CPIO_HEADER_LEN + filename_len]
            if not parsing:
                # Mark as the beginning of the archive.
                previous = pos
                parsing = True

            pos = InitrdReader.align_up(pos + InitrdReader.CPIO_HEADER_LEN + filename_len, InitrdReader.CPIO_ALIGNMENT)
            pos = InitrdReader.align_up(pos + filesize, InitrdReader.CPIO_ALIGNMENT)

            if filename_len == (InitrdReader.CPIO_END_LEN + 1) and filename == InitrdReader.CPIO_END:
                infile.seek(pos)
                parsing = False
                break

            infile.seek(pos)
            buffer = read_bytes_from_open_file(infile, pos, InitrdReader.CPIO_HEADER_AND_TRAILING_LEN)

            magic = buffer[: InitrdReader.CPIO_MAGIC_LEN]
            if magic not in cpio_formats:
                logger.warning("Corrupt CPIO archive (magic: %s)", magic.decode("UTF-8"))
                return pos

            if InitrdReader.is_eof(infile):
                break

        if InitrdReader.is_eof(infile):
            # CPIO_END not found.
            return pos

        # Skip zeros.
        while True:
            i = 0
            buffer = read_bytes_from_open_file(infile, pos, buffer_size)
            for i, value in enumerate(buffer):
                if value != 0:
                    break

            if buffer[i] != 0:
                pos += i
                infile.seek(pos)
                break

            pos += len(buffer)

            if InitrdReader.is_eof(infile):
                # Rewinding, as we got to the end of the archive.
                pos = previous
                break

        return pos

    def _extract(self) -> None:
        """Extract an initrd."""
        with open(self._initrd_file, "rb") as infile:
            InitrdReader.extract_at_offset(infile, self.skip_cpio(infile), self._contents_dir)

    def set_initrd(self, initrdfile: str) -> None:
        """
        Define the initrd to be used.

        Specify an initrd file, that will be extracted. Its contents
        can be found at the path indicated by the method contents().

        :param initrdfile: a string with the path of an initrd
        :return: None
        """
        if not os.path.isfile(initrdfile):
            errmsg = f"Specified initrd file '{initrdfile}' does not seem to exist; please double check"
            logger.error(errmsg)
            raise Exception(errmsg)

        self._initrd_file = os.path.realpath(initrdfile)
        if self._contents_dir and os.path.isdir(self._contents_dir):
            shutil.rmtree(self._contents_dir)
        self._contents_dir = tempfile.mkdtemp(prefix="keylime-initrd-")
        self._extract()

    def contents(self) -> str:
        """
        Return the path where the extracted initrd is available.

        :return: str
        """
        return self._contents_dir

    def __init__(self, initrdfile: str) -> None:
        """
        Initialize the class with the specified initrd.

        :param initrdfile: the path of the initrd we want to extract
        :return: None
        """
        self.set_initrd(initrdfile)

    def __del__(self) -> None:
        """
        Destructor.

        Takes care of removing the temp directory created to contain
        the initrd contents after it has been extracted from the cpio
        archive.

        :return: None
        """
        if self._contents_dir and os.path.isdir(self._contents_dir):
            logger.debug("Removing temporary directory %s", self._contents_dir)
            shutil.rmtree(self._contents_dir)
