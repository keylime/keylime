import base64
import enum
import json
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509 import Certificate, oid
from cryptography.x509.extensions import ExtensionNotFound, SubjectKeyIdentifier

from keylime import keylime_logging

logger = keylime_logging.init_logging("file_signatures")


SupportedKeyTypes = Union[RSAPublicKey, EllipticCurvePublicKey]

"""
Tools for IMA file signature verification
"""


class HashAlgo(enum.IntEnum):
    """The hash_algo's as Linux defines them:
    https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/hash_info.h#L17
    """

    HASH_ALGO_MD4 = 0
    HASH_ALGO_MD5 = 1
    HASH_ALGO_SHA1 = 2
    HASH_ALGO_RIPE_MD_160 = 3
    HASH_ALGO_SHA256 = 4
    HASH_ALGO_SHA384 = 5
    HASH_ALGO_SHA512 = 6
    HASH_ALGO_SHA224 = 7
    HASH_ALGO_RIPE_MD_128 = 8
    HASH_ALGO_RIPE_MD_256 = 9
    HASH_ALGO_RIPE_MD_320 = 10
    HASH_ALGO_WP_256 = 11
    HASH_ALGO_WP_384 = 12
    HASH_ALGO_WP_512 = 13
    HASH_ALGO_TGR_128 = 14
    HASH_ALGO_TGR_160 = 15
    HASH_ALGO_TGR_192 = 16
    HASH_ALGO_TGR_256 = 17
    HASH_ALGO_STREEBOG_256 = 18
    HASH_ALGO_STREEBOG_512 = 19


# Streebog is supported by evmctl
class MyStreebog256(hashes.HashAlgorithm):
    """Basic class for Streebog256"""

    name = "streebog256"  # type: ignore
    digest_size = 32  # type: ignore
    block_size = 64  # type: ignore


class MyStreebog512(hashes.HashAlgorithm):
    """Basic class for Streebog512"""

    name = "streebog512"  # type: ignore
    digest_size = 64  # type: ignore
    block_size = 64  # type: ignore


HASH_FUNCS = {
    # The list of hash functions we need for signature verification.
    HashAlgo.HASH_ALGO_MD5: hashes.__dict__.get("MD5"),
    HashAlgo.HASH_ALGO_SHA1: hashes.__dict__.get("SHA1"),
    HashAlgo.HASH_ALGO_SHA256: hashes.__dict__.get("SHA256"),
    HashAlgo.HASH_ALGO_SHA384: hashes.__dict__.get("SHA384"),
    HashAlgo.HASH_ALGO_SHA512: hashes.__dict__.get("SHA512"),
    HashAlgo.HASH_ALGO_SHA224: hashes.__dict__.get("SHA224"),
    HashAlgo.HASH_ALGO_STREEBOG_256: MyStreebog256,
    HashAlgo.HASH_ALGO_STREEBOG_512: MyStreebog512,
}


class EvmImaXattrType(enum.IntEnum):
    """https://elixir.bootlin.com/linux/v5.9.8/source/security/integrity/integrity.h#L74"""

    IMA_XATTR_DIGEST = 1
    EVM_XATTR_HMAC = 2
    EVM_IMA_XATTR_DIGSIG = 3
    IMA_XATTR_DIGEST_NG = 4
    EVM_XATTR_PORTABLE_DIGSIG = 5


class PubkeyAlgo(enum.IntEnum):
    """https://elixir.bootlin.com/linux/v5.9.8/source/include/linux/digsig.h#L17"""

    PUBKEY_ALGO_RSA = 0


class ImaKeyring:
    """ImaKeyring models an IMA keyring where keys are indexed by their keyid"""

    ringv2: Dict[int, SupportedKeyTypes]

    def __init__(self) -> None:
        """Constructor"""
        self.ringv2 = {}

    @staticmethod
    def _get_keyidv2(pubkey: SupportedKeyTypes) -> int:
        """Calculate the keyidv2 of a given public key object. The keyidv2
        are the lowest 4 bytes of the sha1 hash over the public key bytes
        of a DER-encoded key in PKCS1 format.
        """
        if isinstance(pubkey, RSAPublicKey):
            fmt = serialization.PublicFormat.PKCS1
            pubbytes = pubkey.public_bytes(encoding=serialization.Encoding.DER, format=fmt)
        elif isinstance(pubkey, EllipticCurvePublicKey):
            fmt = serialization.PublicFormat.UncompressedPoint
            pubbytes = pubkey.public_bytes(encoding=serialization.Encoding.X962, format=fmt)
        else:
            raise UnsupportedAlgorithm(f"Unsupported public key type {type(pubkey)}")

        default_be = backends.default_backend()
        digest = hashes.Hash(hashes.SHA1(), backend=default_be)
        digest.update(pubbytes)
        keydigest = digest.finalize()
        return int.from_bytes(keydigest[16:], "big")

    def add_pubkey(self, pubkey: SupportedKeyTypes, keyidv2: Optional[int]) -> None:
        """Add a public key object to the keyring; a keyidv2 may be passed in
        and if it is 'None' it will be determined using the commonly used
        sha1 hash function for calculating the Subject Key Identifier.
        """
        if not keyidv2:
            keyidv2 = ImaKeyring._get_keyidv2(pubkey)
        # it's unlikely that two different public keys have the same 32 bit keyidv2
        self.ringv2[keyidv2] = pubkey
        logger.debug("Added key with keyid: 0x%08x", keyidv2)

    def get_pubkey_by_keyidv2(self, keyidv2: int) -> Optional[SupportedKeyTypes]:
        """Get a public key object given its keyidv2"""
        return self.ringv2.get(keyidv2)

    def to_json(self) -> Dict[str, Union[List[int], List[str]]]:
        """Convert the ImaKeyring into a JSON object"""
        fmt = serialization.PublicFormat.SubjectPublicKeyInfo
        obj: Dict[str, Union[List[int], List[str]]] = {}
        lst = []

        for pubkey in self.ringv2.values():
            try:
                pubbytes = pubkey.public_bytes(encoding=serialization.Encoding.DER, format=fmt)
                lst.append(pubbytes)
            except Exception as ex:
                logger.error("Could not serialize key: %s", str(ex))

        obj["pubkeys"] = [base64.b64encode(pubkey).decode("ascii") for pubkey in lst]
        obj["keyids"] = list(self.ringv2.keys())
        return obj

    def to_string(self) -> str:
        """Generate a string representation"""
        return json.dumps(self.to_json())

    @staticmethod
    def _base64_to_der_keylist(base64_keylist: List[str], keyidv2_list: List[int]) -> List[Tuple[bytes, Optional[int]]]:
        """Convert a base64-encoded list of public keys to a list of DER-encoded
        public keys; a keyidv2_list may also be given that contains
        the keyidv2 of each key
        """
        res = []
        for idx, entry in enumerate(base64_keylist):
            keyidv2 = keyidv2_list[idx] if idx < len(keyidv2_list) else None
            res.append((base64.b64decode(entry), keyidv2))
        return res

    @staticmethod
    def from_string(stringrepr: str) -> Optional["ImaKeyring"]:
        """Convert a string-encoded ImaKeyring to an ImaKeyring object"""
        if not stringrepr:
            return None

        ima_keyring = ImaKeyring()

        default_be = backends.default_backend()

        # An empty Db entry comes as a string 'null' or previously '[]'. A valid DB entry
        # is a string with escaped quotes and needs to be loaded twice
        obj = json.loads(stringrepr)
        if isinstance(obj, str):
            obj = json.loads(obj)
        if not isinstance(obj, dict):
            return None

        keyids = obj.get("keyids", [])

        for (der_key, keyidv2) in ImaKeyring._base64_to_der_keylist(obj["pubkeys"], keyids):
            try:
                pubkey = serialization.load_der_public_key(der_key, backend=default_be)
                if not isinstance(pubkey, (RSAPublicKey, EllipticCurvePublicKey)):
                    raise ValueError(f"Unsupported key type {type(pubkey).__name__}")
                ima_keyring.add_pubkey(pubkey, keyidv2)
            except Exception as ex:
                logger.error("Could not load a base64-decoded DER key: %s", str(ex))
        return ima_keyring


class ImaKeyrings:
    """IMA Keyrings models the various keyrings of the system where IMA may take its keys from"""

    keyrings: Dict[str, ImaKeyring]

    def __init__(self) -> None:
        """Constructor"""
        self.keyrings = {}

    def add_to_keyring_from_data(self, filedata: bytes, keyring_name: str) -> None:
        """Add the public key, given as a plain filedata (bytes), to the keyring by the given name
        after converting the key to an object. If a keyring by the given name doesn't exist, one
        will be created."""
        pubkey, keyidv2 = get_pubkey(filedata)
        if pubkey:
            self.add_pubkey_to_keyring(pubkey, keyring_name, keyidv2=keyidv2)

    def add_pubkey_to_keyring(
        self, pubkey: SupportedKeyTypes, keyring_name: str, keyidv2: Optional[int] = None
    ) -> None:
        """Add a public key object to a keyring by the given name. If a keyring by the given name
        doesn't exist, one will be created."""
        keyring = self.keyrings.get(keyring_name)
        if not keyring:
            keyring = ImaKeyring()
            self.keyrings[keyring_name] = keyring
        keyring.add_pubkey(pubkey, keyidv2)

    def set_tenant_keyring(self, tenant_keyring: Optional[ImaKeyring]) -> None:
        """Set the tenant keyring for which the tenant provided the keys via command line."""
        if tenant_keyring:
            self.keyrings["tenant_keyring"] = tenant_keyring
        else:
            self.keyrings.pop("tenant_keyring", None)

    def get_tenant_keyring(self) -> Optional[ImaKeyring]:
        """Get the tenant keyring."""
        return self.keyrings.get("tenant_keyring")

    def get_all_keyrings(self) -> List[ImaKeyring]:
        """Get a list of all the keyrings"""
        return list(self.keyrings.values())

    def to_json(self) -> Dict[str, str]:
        """Convert an ImaKeyrings into its JSON representation; this does not include the tenant keyring"""
        obj = {}

        for name, keyring in self.keyrings.items():
            if name == "tenant_keyring":
                continue
            obj[name] = keyring.to_string()

        return obj

    def to_string(self) -> str:
        """Convert an ImaKeyrings into its string representation; this does not include the tenant keyring"""
        return json.dumps(self.to_json())

    @staticmethod
    def from_string(stringrepr: str) -> Optional["ImaKeyrings"]:
        """Convert a string-encoded ImaKeyrings into an ImaKeyrings object."""

        obj = json.loads(stringrepr)
        if isinstance(obj, str):
            obj = json.loads(obj)
        if not isinstance(obj, dict):
            return None

        return ImaKeyrings.from_json(obj)

    @staticmethod
    def from_json(obj: Dict[str, str]) -> "ImaKeyrings":
        """Convert a JSON representation of an ImaKeyrings object to an ImaKeyrings object."""
        ima_keyrings = ImaKeyrings()

        for name, keyring_str in obj.items():
            ima_keyring = ImaKeyring.from_string(keyring_str)
            if ima_keyring:
                ima_keyrings.keyrings[name] = ima_keyring

        return ima_keyrings

    @staticmethod
    def _verify(pubkey: SupportedKeyTypes, sig: bytes, filehash: bytes, hashfunc: hashes.HashAlgorithm) -> None:
        """Do signature verification with the given public key"""
        if isinstance(pubkey, RSAPublicKey):
            pubkey.verify(sig, filehash, padding.PKCS1v15(), Prehashed(hashfunc))
        elif isinstance(pubkey, EllipticCurvePublicKey):
            pubkey.verify(sig, filehash, ec.ECDSA(Prehashed(hashfunc)))

    def _asymmetric_verify(self, signature: bytes, filehash: bytes, filehash_type: str) -> bool:
        """Do an IMA signature verification given the signature data from
        the log, which is formatted as 'struct signature_v2_hdr'.
        This function resembles the kernel code:
        https://elixir.bootlin.com/linux/v5.9/source/security/integrity/digsig_asymmetric.c#L76
        https://elixir.bootlin.com/linux/v5.9/source/security/integrity/integrity.h#L116
        """

        siglen = len(signature)

        # The data are in big endian
        fmt = ">BBBIH"
        hdrlen = struct.calcsize(fmt)
        if len(signature) < hdrlen:
            logger.warning("Signature header is too short")
            return False
        _, _, hash_algo, keyidv2, sig_size = struct.unpack(fmt, signature[:hdrlen])

        siglen -= hdrlen

        if siglen != sig_size:
            logger.warning("Malformed signature")
            return False

        hashfunc = HASH_FUNCS.get(hash_algo)
        if not hashfunc:
            logger.warning("Unsupported hash algo with id '%d'", hash_algo)
            return False

        if filehash_type != hashfunc().name:
            logger.warning(
                "Mismatching filehash type %s and ima signature hash used %s", filehash_type, hashfunc().name
            )
            return False

        # Try all the keyrings until we find one with a key with the given keyidv2
        pubkey = None
        for keyring in self.get_all_keyrings():
            pubkey = keyring.get_pubkey_by_keyidv2(keyidv2)
            if pubkey:
                break

        if not pubkey:
            logger.warning("No key with id 0x%08x available", keyidv2)
            return False

        try:
            ImaKeyrings._verify(pubkey, signature[hdrlen:], filehash, hashfunc())
        except InvalidSignature:
            return False
        return True

    def integrity_digsig_verify(self, signature: bytes, filehash: bytes, filehash_type: str) -> bool:
        """Validate the signature against the given hash trying all keyrings.
        This function resembles the kernel code at:
        https://elixir.bootlin.com/linux/v5.9/source/security/integrity/digsig.c#L59
        """
        fmt = ">BB"
        if len(signature) < struct.calcsize(fmt):
            logger.warning("Malformed signature: not enough bytes")
            return False

        typ, version = struct.unpack(fmt, signature[: struct.calcsize(fmt)])
        if typ not in [EvmImaXattrType.EVM_IMA_XATTR_DIGSIG, EvmImaXattrType.EVM_XATTR_PORTABLE_DIGSIG]:
            logger.warning("Malformed signature: wrong type")
            return False

        if version == 2:
            return self._asymmetric_verify(signature, filehash, filehash_type)

        logger.warning("Malformed signature: wrong version (%d)", version)
        return False


def _get_pubkey_from_der_public_key(filedata: bytes, backend: Any) -> Tuple[Any, None]:
    """Load the filedata as a DER public key"""
    try:
        return serialization.load_der_public_key(filedata, backend=backend), None
    except Exception:
        return None, None


def _get_pubkey_from_pem_public_key(filedata: bytes, backend: Any) -> Tuple[Any, None]:
    """Load the filedata as a PEM public key"""
    try:
        return serialization.load_pem_public_key(filedata, backend=backend), None
    except Exception:
        return None, None


def _get_pubkey_from_der_private_key(filedata: bytes, backend: Any) -> Tuple[Any, None]:
    """Load the filedata as a DER private key"""
    try:
        privkey = serialization.load_der_private_key(filedata, None, backend=backend)
        return privkey.public_key(), None
    except Exception:
        return None, None


def _get_pubkey_from_pem_private_key(filedata: bytes, backend: Any) -> Tuple[Any, None]:
    """Load the filedata as a PEM private key"""
    try:
        privkey = serialization.load_pem_private_key(filedata, None, backend=backend)
        return privkey.public_key(), None
    except Exception:
        return None, None


def _get_keyidv2_from_cert(cert: Certificate) -> Optional[int]:
    """Get the keyidv2 from the cert's Subject Key Identifier (SKID) if available."""
    if cert.extensions:
        try:
            skid = cert.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            if skid and skid.value and isinstance(skid.value, SubjectKeyIdentifier) and len(skid.value.digest) >= 4:
                keyidv2 = int.from_bytes(skid.value.digest[-4:], "big")
                logger.debug("Extracted keyidv2 from cert: 0x%08x", keyidv2)
                return keyidv2
        except ExtensionNotFound:
            pass

    logger.warning("Certificate doesn't have a Subject Key Identifier; keyidv2 will be derived from public key")
    return None


def _get_pubkey_from_der_x509_certificate(filedata: bytes, backend: Any) -> Tuple[Any, Optional[int]]:
    """Load the filedata as a DER x509 certificate"""
    try:
        cert = x509.load_der_x509_certificate(filedata, backend=backend)
        return cert.public_key(), _get_keyidv2_from_cert(cert)
    except Exception:
        return None, None


def _get_pubkey_from_pem_x509_certificate(filedata: bytes, backend: Any) -> Tuple[Any, Optional[int]]:
    """Load the filedata as a PEM x509 certificate"""
    try:
        cert = x509.load_pem_x509_certificate(filedata, backend=backend)
        return cert.public_key(), _get_keyidv2_from_cert(cert)
    except Exception:
        return None, None


def get_pubkey(filedata: bytes) -> Tuple[Optional[SupportedKeyTypes], Optional[int]]:
    """Get the public key from the filedata; if an x509 certificate is
    given, also determine the keyidv2 from the Subject Key Identifier,
    otherwise return None
    To make it easy for the user, we try to parse the filedata as
    PEM- or DER-encoded public key, x509 certificate, or even private key.
    This function then returns the public key object or None if the file
    contents could not be interpreted as a key.
    """
    default_be = backends.default_backend()
    for func in [
        _get_pubkey_from_der_x509_certificate,
        _get_pubkey_from_pem_x509_certificate,
        _get_pubkey_from_der_public_key,
        _get_pubkey_from_pem_public_key,
        _get_pubkey_from_der_private_key,
        _get_pubkey_from_pem_private_key,
    ]:
        pubkey, keyidv2 = func(filedata, default_be)
        if pubkey:
            if not isinstance(pubkey, (RSAPublicKey, EllipticCurvePublicKey)):
                raise ValueError(f"Unsupported key type {type(pubkey).__name__}")
            return pubkey, keyidv2

    return None, None


def get_pubkey_from_file(filename: str) -> Tuple[Optional[SupportedKeyTypes], Optional[int]]:
    """Get the public key object from a file"""
    with open(filename, "rb") as fobj:
        filedata = fobj.read()
        pubkey, keyidv2 = get_pubkey(filedata)
        if pubkey:
            if not isinstance(pubkey, (RSAPublicKey, EllipticCurvePublicKey)):
                raise ValueError(f"Unsupported key type {type(pubkey).__name__}")
            return pubkey, keyidv2

    return None, None
