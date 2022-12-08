import enum
import hashlib
from typing import Any, List, cast


def is_accepted(algorithm: str, accepted: List[Any]) -> bool:
    """Check whether algorithm is accepted

    @param algorithm: algorithm to be checked
    @param accepted: a list of acceptable algorithms
    """
    return algorithm in accepted


class Hash(str, enum.Enum):
    # Names compatible with tpm2-tools (man/common/alg.md)
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SM3_256 = "sm3_256"

    @classmethod
    def from_algorithm(cls, algorithm: str) -> "Hash":
        return cls(algorithm)

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        try:
            Hash(algorithm).get_size()
        except ValueError:
            return False
        return True

    def __hashfn(self, data: bytes) -> Any:
        # Translate from tmp2-tools name into hashlib.new() name
        alg = "sm3" if self.value == "sm3_256" else self.value
        return hashlib.new(alg, data)

    def hash(self, data: bytes) -> bytes:
        return cast(bytes, self.__hashfn(data).digest())

    def get_size(self) -> int:
        return cast(int, self.__hashfn(b"").digest_size * 8)

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
