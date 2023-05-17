import struct
from typing import Dict, List, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from keylime import keylime_logging
from keylime.tpm import tpm2_objects

logger = keylime_logging.init_logging("tpm_util")

SupportedKeyTypes = Union[RSAPublicKey, EllipticCurvePublicKey]


def verify(pubkey: SupportedKeyTypes, sig: bytes, digest: bytes, hashfunc: hashes.HashAlgorithm) -> None:
    """Do signature verification with the given public key"""
    if isinstance(pubkey, RSAPublicKey):
        pubkey.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashfunc))
    elif isinstance(pubkey, EllipticCurvePublicKey):
        pubkey.verify(sig, digest, ec.ECDSA(Prehashed(hashfunc)))


def __get_pcrs_from_blob(pcrblob: bytes) -> Tuple[int, Dict[int, int], List[bytes]]:
    """This function is specific to the Intel tools with data in little endian format.
    Data structures were not marshalled but written right from memory."""
    # TPML_PCR_SELECTION:count
    (pcr_select_count,) = struct.unpack_from("<I", pcrblob, 0)

    o = 4
    # TPML_PCR_SELECTION:TPMS_PCR_SELECTION[HASH_COUNT]
    tpml_pcr_selection: Dict[int, int] = {}
    for _ in range(0, 16):
        hash_alg, size_of_select = struct.unpack_from("<HB", pcrblob, o)
        if size_of_select not in [0, 3]:
            raise ValueError(f"size_of_select must be either 0 or 3 but it is {size_of_select}")
        o = o + 3

        if size_of_select == 3:
            (pcr_select_bytes,) = struct.unpack_from("3s", pcrblob, o)
            pcr_select = pcr_select_bytes[0] | pcr_select_bytes[1] << 8 | pcr_select_bytes[2] << 16
        else:
            pcr_select = 0

        tpml_pcr_selection[hash_alg] = pcr_select

        # always advance by size_of_select = 3 and 2 bytes alignment
        o = o + 3 + 2

    # Number of subsequent TPML_DIGEST's
    (pcrs_count,) = struct.unpack_from("<I", pcrblob, o)
    o = o + 4

    pcr_values: List[bytes] = []

    for _ in range(0, pcrs_count):
        # TPML_DIGEST::count
        (_,) = struct.unpack_from("<I", pcrblob, o)
        o = o + 4

        # TPML_DIGEST::TPM2B_DIGEST[8]
        for _ in range(0, 8):
            (sz,) = struct.unpack_from("<H", pcrblob, o)
            o = o + 2
            if sz:
                (pcr_value,) = struct.unpack_from(f"{sz}s", pcrblob, o)
                pcr_values.append(pcr_value)
            # Always advance by the size of TPMU_HA (= size of SHA512)
            o = o + 64

    if o != len(pcrblob):
        raise ValueError("Failed to parse the entire pcrblob")

    return pcr_select_count, tpml_pcr_selection, pcr_values


def __hash_pcr_banks(
    hash_alg: int, pcr_select_count: int, tpml_pcr_selection: Dict[int, int], pcr_values: List[bytes]
) -> Tuple[bytes, Dict[int, str]]:
    """From the tpml_pcr_selection determine which PCRs were quoted and hash these PCRs to get
    the hash that was used for the quote. Build a dict that contains the PCR values."""
    hashfunc = tpm2_objects.HASH_FUNCS.get(hash_alg)
    if not hashfunc:
        raise ValueError(f"Unsupported hash with id {hash_alg:#x} in signature blob")

    digest = hashes.Hash(hashfunc, backend=backends.default_backend())

    idx = 0
    pcrs_dict: Dict[int, str] = {}

    for _ in range(0, pcr_select_count):
        for pcr_id in range(0, 24):
            if tpml_pcr_selection[hash_alg] & (1 << pcr_id) == 0:
                continue
            if idx >= len(pcr_values):
                raise ValueError(f"pcr_values list is too short to get item {idx}")
            digest.update(pcr_values[idx])
            pcrs_dict[pcr_id] = pcr_values[idx].hex()
            idx = idx + 1

    if idx != len(pcr_values):
        raise ValueError("Did not consume all entries in pcr_values list")

    quote_digest = digest.finalize()

    return quote_digest, pcrs_dict


def __get_and_hash_pcrs(pcrblob: bytes, hash_alg: int) -> Tuple[bytes, Dict[int, str]]:
    pcr_select_count, tpml_pcr_selection, pcr_values = __get_pcrs_from_blob(pcrblob)
    return __hash_pcr_banks(hash_alg, pcr_select_count, tpml_pcr_selection, pcr_values)


def checkquote(
    aikblob: bytes, nonce: str, sigblob: bytes, quoteblob: bytes, pcrblob: bytes, exp_hash_alg: str
) -> Dict[int, str]:
    """Check the given quote by checking the signature, then the nonce and then the used hash

    Parameters
    ----------
    aikblob: PEM-formatted public RSA or EC key
    nonce: The nonce that was used during the quote
    sigblob: Signature blob containing signature algorithm, hash used for signing, and plain signature
    quoteblob: Marshalled TPMS_ATTEST
    pcrblob: The state of the PCRs that were quoted; Intel tpm2-tools specific format
    exp_hash_alg: The hash that was expected to have been used for quoting
    """
    sig_alg, hash_alg, sig_size = struct.unpack_from(">HHH", sigblob, 0)

    (signature,) = struct.unpack_from(f"{sig_size}s", sigblob, 6)

    pubkey = serialization.load_pem_public_key(aikblob, backend=backends.default_backend())
    if not isinstance(pubkey, (RSAPublicKey, EllipticCurvePublicKey)):
        raise ValueError(f"Unsupported key type {type(pubkey).__name__}")

    if isinstance(pubkey, RSAPublicKey) and sig_alg not in [tpm2_objects.TPM_ALG_RSASSA]:
        raise ValueError(f"Unsupported quote signature algorithm '{sig_alg:#x}' for RSA keys")
    if isinstance(pubkey, EllipticCurvePublicKey) and sig_alg not in [tpm2_objects.TPM_ALG_ECDSA]:
        raise ValueError(f"Unsupported quote signature algorithm '{sig_alg:#x}' for EC keys")

    hashfunc = tpm2_objects.HASH_FUNCS.get(hash_alg)
    if not hashfunc:
        raise ValueError(f"Unsupported hash with id {hash_alg:#x} in signature blob")
    if hashfunc.name != exp_hash_alg:
        raise ValueError(f"Quote was expected to use {exp_hash_alg} but used {hashfunc.name} instead")

    digest = hashes.Hash(hashfunc, backend=backends.default_backend())
    digest.update(quoteblob)
    quote_digest = digest.finalize()

    try:
        verify(pubkey, signature, quote_digest, hashfunc)
    except InvalidSignature:
        logger.error("Invalid quote signature!")

    # Check that reported nonce is expected one
    retDict = tpm2_objects.unmarshal_tpms_attest(quoteblob)
    extradata = retDict["extraData"]
    if extradata.decode("utf-8") != nonce:
        raise Exception("The nonce from the attestation differs from the expected nonce")

    # Check that correct quote_digest was used which is equivalent to hash(quoteblob)
    compare_digest, pcrs_dict = __get_and_hash_pcrs(pcrblob, hash_alg)
    if retDict["attested.quote.pcrDigest"] != compare_digest:
        raise Exception("The digest used for quoting is different than the one that was calculated")

    digest = hashes.Hash(hashfunc, backend=backends.default_backend())
    digest.update(quoteblob)
    quoteblob_digest = digest.finalize()

    if quoteblob_digest != quote_digest:
        raise Exception("The digest of the quoteblob differs from the quote's digest")

    return pcrs_dict
