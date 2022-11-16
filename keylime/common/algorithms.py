import enum
import hashlib
from typing import Any, List


def is_accepted(algorithm: str, accepted: List[Any]) -> bool:
    """Check whether algorithm is accepted

    @param algorithm: algorithm to be checked
    @param accepted: a list of acceptable algorithms
    """
    return algorithm in accepted


def _hashit(algorithm: str, data: bytes) -> bytes:
    if algorithm == "sha1":
        return hashlib.sha1(data).digest()
    if algorithm == "sha256":
        return hashlib.sha256(data).digest()
    if algorithm == "sha384":
        return hashlib.sha384(data).digest()
    if algorithm == "sha512":
        return hashlib.sha512(data).digest()
    if algorithm == "sm3_256":
        # SM3 is not guaranteed to be there
        return hashlib.new("sm3", data).digest()

    raise ValueError(f"Unsupported hash algorithm {algorithm}")


class Hash(str, enum.Enum):
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SM3_256 = "sm3_256"

    def __init__(self, *args):  # pylint: disable=unused-argument
        super().__init__()
        # Test hash to raise ValueError for unsupported hashes
        _hashit(self.value, b"")

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        try:
            Hash(algorithm)
            return True
        except ValueError:
            return False

    def hash(self, data: bytes) -> bytes:
        return _hashit(self.value, data)

    def get_size(self) -> int:
        return _HASH_SIZE[self]

    def __str__(self) -> str:
        return self.value


class Encrypt:
    RSA = "rsa"
    ECC = "ecc"
    supported_algorithms = (RSA, ECC)

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        return algorithm in Encrypt.supported_algorithms


class Sign:
    RSASSA = "rsassa"
    RSAPSS = "rsapss"
    ECDSA = "ecdsa"
    ECDAA = "ecdaa"
    ECSCHNORR = "ecschnorr"
    supported_algorithms = (RSASSA, RSAPSS, ECDSA, ECDAA, ECSCHNORR)

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        return algorithm in Sign.supported_algorithms


_HASH_SIZE = {
    Hash.SHA1: 160,
    Hash.SHA256: 256,
    Hash.SHA384: 384,
    Hash.SHA512: 512,
    Hash.SM3_256: 256,
}
