#!/usr/bin/env python3

"""Analyze local and remote RPM repositories."""

import gzip
import multiprocessing
import os
import pathlib
import shutil
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from typing import Dict, Generator, List, Optional, Tuple

import rpm  # pylint: disable=import-error

from keylime.common import algorithms
from keylime.policy.logger import Logger
from keylime.policy.utils import Compression, merge_maplists
from keylime.signing import verify_signature_from_file
from keylime.types import PathLike_str

logger = Logger().logger()


def _parse_rpm_header(hdr: rpm.hdr) -> Tuple[Dict[str, List[str]], Dict[str, List[bytes]]]:
    # First, the file digests.
    _MD5_DIGEST_LEN = 32  # In the past, rpm used MD5 for the digests.
    _SHA256_DIGEST_LEN = algorithms.Hash("sha256").hexdigest_len()
    empty_hashes = ("0" * _MD5_DIGEST_LEN, "0" * _SHA256_DIGEST_LEN)
    digests = {f.name: [f.digest] for f in rpm.files(hdr) if f.digest not in empty_hashes}

    # Now, the IMA signatures, if any.
    ima_sig = {f.name: [f.imasig] for f in rpm.files(hdr) if f.imasig}
    return digests, ima_sig


def analyze_rpm_pkg(pkg: PathLike_str) -> Tuple[Dict[str, List[str]], Dict[str, List[bytes]]]:
    """
    Analyze a single RPM package.

    :param pkg: the path to a single package
    :return: two dicts; the first one containts the digests of the files and the
             second one contains the ima signatures, if any
    """
    ts = rpm.TransactionSet()
    ts.setVSFlags(rpm.RPMVSF_MASK_NOSIGNATURES | rpm.RPMVSF_MASK_NODIGESTS)

    with open(pkg, "rb") as f:
        hdr = ts.hdrFromFdno(f)

    # Symbolic links in IMA are resolved before the measured,
    # registering the final linked name in the logs
    return _parse_rpm_header(hdr)


def analyze_rpm_pkg_url(url: str) -> Tuple[Dict[str, List[str]], Dict[str, List[bytes]]]:
    """Analyze a single RPM package from its URL."""
    # To fetch the header we can emulate rpmReadPackageFile, but this
    # seems to require multiple reads.  This simplified algorithm read
    # first a sizeable blob, adjusted from the median of some repo
    # analysis, and if the hdrFromFdno fails, try to expand it
    # iteratively.

    # Estimation of a RPM header size.
    _RPM_HEADER_SIZE = 24 * 1024

    # Hide errors while fetching partial headers.
    with open(os.devnull, "wb") as devnull:
        rpm.setLogFile(devnull)

        logmsg = f"Fetching header for {url}"
        logger.debug(logmsg)

        blob = b""
        chunk_size = _RPM_HEADER_SIZE
        while True:
            with tempfile.TemporaryFile() as f:
                range_ = f"{len(blob)}-{len(blob) + chunk_size - 1}"
                req = urllib.request.Request(url, headers={"Range": f"bytes={range_}"})
                try:
                    with urllib.request.urlopen(req) as resp:
                        blob += resp.read()
                except urllib.error.HTTPError as exc:
                    errmsg = f"Error trying to open {url}: {exc}"
                    logger.warning(errmsg)
                    return {}, {}

                f.write(blob)
                f.seek(0)

                ts = rpm.TransactionSet()
                ts.setVSFlags(rpm.RPMVSF_MASK_NOSIGNATURES | rpm.RPMVSF_MASK_NODIGESTS)
                try:
                    hdr = ts.hdrFromFdno(f)
                    break
                except Exception:
                    chunk_size = max(1024, int(chunk_size / 2))

    # Symbolic links in IMA are resolved before the measured,
    # registering the final linked name in the logs
    return _parse_rpm_header(hdr)


def analyze_local_repo(
    *repodir: str,
    digests: Optional[Dict[str, List[str]]] = None,
    imasigs: Optional[Dict[str, List[bytes]]] = None,
    jobs: Optional[int] = None,
) -> Tuple[Dict[str, List[str]], Dict[str, List[bytes]], bool]:
    """
    Analyze a local repository.

    :param *repodir: str, the directory of the repository, where "repodata" is
           located
    :param digests: dict of str and a list of strings, to store the files and
                     their associated digests
    :param imasigs: dict of str and a list of bytes, to store the files and
                       their associated IMA signatures
    :param jobs: integer, the number of jobs to use when processing the rpms
    :return: tuple with the dict of digests, the dict of IMA signatures and a
             boolean indicating the success of this method
    """
    # Validate repodir.
    if not str(*repodir):
        logger.error("Please specify a repository")
        return {}, {}, False

    repo = pathlib.Path(*repodir)
    if not repo.exists():
        errmsg = f"{repo.absolute()} does not seem to exist"
        logger.error(errmsg)
        return {}, {}, False

    repodata_dir = repo.joinpath("repodata")
    if not repodata_dir.exists():
        errmsg = f"{repodata_dir.absolute()} does not seem to exist"
        logger.error(errmsg)
        return {}, {}, False

    repomd_xml = repodata_dir.joinpath("repomd.xml")
    if not repomd_xml.exists():
        errmsg = f"{repomd_xml} cannot be found"
        logger.error(errmsg)
        return {}, {}, False

    repomd_asc = repodata_dir.joinpath("repomd.xml.asc")
    if repomd_asc.exists():
        repomd_key = repodata_dir.joinpath("repomd.xml.key")
        if not repomd_key.exists():
            errmsg = f"Error. Key file {repomd_key} missing"
            logger.error(errmsg)
            return {}, {}, False

        try:
            verify_signature_from_file(repomd_key, repomd_xml, repomd_asc, "Repository metadata")
        except Exception:
            logger.error("Error. Invalid signature. Untrusted repository")
            return {}, {}, False
    else:
        logger.warning("Warning. Unsigned repository. Continuing the RPM scanning")

    jobs = jobs if jobs else multiprocessing.cpu_count()

    if not digests:
        digests = {}
    if not imasigs:
        imasigs = {}

    # Analyze all the RPMs in parallel
    with multiprocessing.Pool(jobs) as pool:
        for rpm_digests, rpm_imasigs in pool.map(analyze_rpm_pkg, repo.glob("**/*.rpm")):
            digests = merge_maplists(digests, rpm_digests)
            imasigs = merge_maplists(imasigs, rpm_imasigs)

    return digests, imasigs, True


@contextmanager
def get_from_url(url: str) -> Generator[str, None, None]:
    """Download the contents of an URL."""
    try:
        with urllib.request.urlopen(url) as resp:
            tfile = None
            try:
                tfile = tempfile.NamedTemporaryFile(prefix="keylime-policy-rpm-repo", delete=False)
                fname = tfile.name
                shutil.copyfileobj(resp, tfile)
                tfile.close()
                yield fname
            finally:
                if tfile:
                    os.remove(tfile.name)
    except (urllib.error.HTTPError, ValueError) as exc:
        logger.debug("HTTP error with URL '%s': %s", url, exc)
        yield ""


def get_filelists_ext_from_repomd(repo: str, repomd_xml: str) -> Optional[str]:
    """Parse the filelist_ext file from a given repomd.xml file."""
    root = _parse_xml_file(repomd_xml).getroot()
    location = root.find(
        "./{http://linux.duke.edu/metadata/repo}data[@type='filelists-ext']/{http://linux.duke.edu/metadata/repo}location"
    )
    return urllib.parse.urljoin(repo, location.attrib["href"]) if location is not None else None


def get_rpm_urls_from_repomd(repo: str, repomd_xml: str) -> List[str]:
    """Parse the RPM URLs from a given repomd.xml file."""
    root = _parse_xml_file(repomd_xml).getroot()
    location = root.find(
        "./{http://linux.duke.edu/metadata/repo}data[@type='primary']/{http://linux.duke.edu/metadata/repo}location"
    )
    if location is None:
        logger.error("Error. Primary location tag not found")
        return []

    logger.debug("Generating package list from repo ...")
    primary_xml_url = urllib.parse.urljoin(repo, location.attrib["href"])
    with get_from_url(primary_xml_url) as primary_xml:
        if not primary_xml:
            logger.error("Error. Primary XML file cannot be downloaded")
            return []

        root = _parse_xml_file(primary_xml)

        locations = root.findall(
            "./{http://linux.duke.edu/metadata/common}package[@type='rpm']"
            "/{http://linux.duke.edu/metadata/common}location"
        )

        return [urllib.parse.urljoin(repo, ll.attrib["href"]) for ll in locations]


def _parse_xml_file(filepath: str) -> ET.ElementTree:
    # We support only gzip compression, currently.
    ctype = Compression.detect_from_file(filepath)
    if ctype:
        if ctype != Compression.GZIP:
            errmsg = (
                f"Compression type '{ctype}' NOT supported yet; The only compression format currently supported is gzip"
            )
            logger.debug(errmsg)
            raise Exception(errmsg)
        # Gzip.
        with gzip.open(filepath) as to_parse:
            return ET.parse(to_parse)

    # Let us assume no compression here.
    with open(filepath, encoding="UTF-8") as to_parse:
        return ET.parse(to_parse)


def _analyze_remote_repo(
    repo: str, digests: Optional[Dict[str, List[str]]], imasigs: Optional[Dict[str, List[bytes]]], jobs: Optional[int]
) -> Tuple[Dict[str, List[str]], Dict[str, List[bytes]], bool]:
    # Make the repo ends with "/", so we can be considered as a base URL
    repo = repo if (repo).endswith("/") else f"{repo}/"

    if not digests:
        digests = {}
    if not imasigs:
        imasigs = {}

    repomd_xml_url = urllib.parse.urljoin(repo, "repodata/repomd.xml")
    with get_from_url(repomd_xml_url) as repomd_xml:
        if not repomd_xml:
            errmsg = f"{repomd_xml_url} cannot be found"
            logger.error(errmsg)
            return {}, {}, False

        repomd_asc_url = urllib.parse.urljoin(repo, "repodata/repomd.xml.asc")
        print("ASC", repomd_asc_url)
        with get_from_url(repomd_asc_url) as repomd_asc:
            if repomd_asc:
                repomd_key_url = urllib.parse.urljoin(repo, "repodata/repomd.xml.key")
                with get_from_url(repomd_key_url) as repomd_key:
                    if not repomd_key:
                        errmsg = f"Error. Key file {repomd_key_url} missing"
                        logger.error(errmsg)
                        return {}, {}, False
                    try:
                        verify_signature_from_file(repomd_key, repomd_xml, repomd_asc, "Repository metadata")
                    except Exception:
                        logger.error("Error. Invalid signature. Untrusted repository")
                        return {}, {}, False
            else:
                logger.warning("Warning. Unsigned repository. Continuing the RPM scanning")

        # Check if this repo contains the filelists-ext.xml metadata
        filelists_ext_xml_url = get_filelists_ext_from_repomd(repo, repomd_xml)
        if filelists_ext_xml_url:
            with get_from_url(filelists_ext_xml_url) as filelists_ext_xml:
                if not filelists_ext_xml:
                    errmsg = f"{filelists_ext_xml_url} cannot be found"
                    logger.error(errmsg)
                    return {}, {}, False

                root = _parse_xml_file(filelists_ext_xml)
                files = root.findall(".//{http://linux.duke.edu/metadata/filelists-ext}file[@hash]")
                for f in files:
                    if not f.text:
                        continue
                    v = digests.get(f.text, [])
                    v.append(f.attrib["hash"])
                    digests[f.text] = v

                return digests, imasigs, True

        # If not, use the slow method
        logger.warning("Warning. filelist-ext.xml not present in the repo")
        rpms = get_rpm_urls_from_repomd(repo, repomd_xml)

    # The default job selection is a bit weird.  The issue is that
    # seems that librpm can be not always thread safe, so we can use a
    # single thread (asyncio) or multiple process.  To avoid change
    # all the stack, I go for synchronous functions but with many
    # process.  In the future we can move all to asyncio.
    jobs = jobs if jobs else (multiprocessing.cpu_count() * 8)

    # Analyze all the RPMs in parallel
    with multiprocessing.Pool(jobs) as pool:
        for rpm_digests, rpm_imasigs in pool.map(analyze_rpm_pkg_url, rpms):
            digests = merge_maplists(digests, rpm_digests)
            imasigs = merge_maplists(imasigs, rpm_imasigs)

    return digests, imasigs, True


def analyze_remote_repo(
    *repourl: str,
    digests: Optional[Dict[str, List[str]]] = None,
    imasigs: Optional[Dict[str, List[bytes]]] = None,
    jobs: Optional[int] = None,
) -> Tuple[Dict[str, List[str]], Dict[str, List[bytes]], bool]:
    """Analyze a remote repository."""
    try:
        return _analyze_remote_repo(str(*repourl), digests, imasigs, jobs)
    except Exception as exc:
        logger.error(exc)
        return {}, {}, False
