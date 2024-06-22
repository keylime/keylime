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

    def get_start_hash(self) -> bytes:
        return b"\x00" * (self.get_size() // 8)

    def get_ff_hash(self) -> bytes:
        return b"\xff" * (self.get_size() // 8)

    def hexdigest_len(self) -> int:
        return len(self.__hashfn(b"").hexdigest())

    def file_digest(self, filepath: str) -> str:
        """
        Calculate the digest of the specified file.

        :param filepath: the path of the file to calculate the digest
        :return: str, the hex digest of the specified file
        """
        _BUFFER_SIZE = 65535
        alg = "sm3" if self.value == "sm3_256" else self.value
        hasher = hashlib.new(alg)
        with open(filepath, "rb") as f:
            while True:
                data = f.read(_BUFFER_SIZE)
                if not data:
                    break
                hasher.update(data)

        return hasher.hexdigest()

    def __str__(self) -> str:
        return self.value


class Encrypt(str, enum.Enum):
    RSA = "rsa"
    ECC = "ecc"

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        return algorithm in list(Encrypt)


class Sign(str, enum.Enum):
    RSASSA = "rsassa"
    RSAPSS = "rsapss"
    ECDSA = "ecdsa"
    ECDAA = "ecdaa"
    ECSCHNORR = "ecschnorr"

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        return algorithm in list(Sign)
