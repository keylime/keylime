import enum
import hashlib
from typing import Any, List, cast


def is_accepted(algorithm: str, accepted: List[Any]) -> bool:
    """Check whether algorithm is accepted

    @param algorithm: algorithm to be checked
    @param accepted: a list of acceptable algorithms
    """
    # Check direct match first.
    if algorithm in accepted:
        return True

    # Check if any accepted algorithm normalizes to the same value as our algorithm
    # This handles backwards compatibility cases like "ecc" accepting "ecc256".
    normalized_algorithm = Encrypt.normalize(algorithm)
    for accepted_alg in accepted:
        if Encrypt.normalize(str(accepted_alg)) == normalized_algorithm:
            return True

    return False


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

    def get_hex_size(self) -> int:
        return len(self.__hashfn(b"").hexdigest())

    def get_start_hash(self) -> bytes:
        return b"\x00" * (self.get_size() // 8)

    def get_ff_hash(self) -> bytes:
        return b"\xff" * (self.get_size() // 8)

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


class Key(str, enum.Enum):
    RSA = "rsa"
    ECC = "ecc"

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        return algorithm in list(Key)


class Encrypt(str, enum.Enum):
    RSA = "rsa"
    RSA1024 = "rsa1024"
    RSA2048 = "rsa2048"
    RSA3072 = "rsa3072"
    RSA4096 = "rsa4096"
    ECC = "ecc"
    ECC192 = "ecc192"
    ECC224 = "ecc224"
    ECC256 = "ecc256"
    ECC384 = "ecc384"
    ECC521 = "ecc521"

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        # Handle aliases to match agent behavior
        if algorithm == "ecc":
            algorithm = "ecc256"  # Default ECC alias maps to P-256, same as the agent.
        if algorithm == "rsa":
            algorithm = "rsa2048"  # Default RSA alias maps to RSA-2048, same as the agent.
        return algorithm in list(Encrypt)

    @staticmethod
    def normalize(algorithm: str) -> str:
        """Normalize algorithm string to handle aliases, matching the agent behavior"""
        if algorithm == "ecc":
            return "ecc256"  # Default ECC alias maps to P-256.
        if algorithm == "rsa":
            return "rsa2048"  # Default RSA alias maps to RSA-2048.
        return algorithm


class Sign(str, enum.Enum):
    RSASSA = "rsassa"
    RSAPSS = "rsapss"
    ECDSA = "ecdsa"
    ECDAA = "ecdaa"
    ECSCHNORR = "ecschnorr"

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        return algorithm in list(Sign)

    @property
    def key_algorithm(self) -> Key:
        if self.value.startswith("rsa"):
            return Key("rsa")
        if self.value.startswith("ec"):
            return Key("ecc")
        raise NotImplementedError(f"key algorithm for signature scheme '{self.value}' is not known")
