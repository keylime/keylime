"""
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Kaifeng Wang
"""
import enum
import hashlib

from typing import Optional, List, Any


def is_accepted(algorithm: str, accepted: List[Any]) -> bool:
    """Check whether algorithm is accepted

    @param algorithm: algorithm to be checked
    @param accepted: a list of acceptable algorithms
    """
    return algorithm in accepted


class Hash(str, enum.Enum):
    SHA1 = 'sha1'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    SM3_256 = 'sm3_256'

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        try:
            Hash(algorithm)
            return True
        except ValueError:
            return False

    def hash(self, data: bytes) -> Optional[bytes]:
        if self == Hash.SHA1:
            return hashlib.sha1(data).digest()
        if self == Hash.SHA256:
            return hashlib.sha256(data).digest()
        if self == Hash.SHA384:
            return hashlib.sha384(data).digest()
        if self == Hash.SHA512:
            return hashlib.sha512(data).digest()
        if self == Hash.SM3_256:
            # SM3 might not be guaranteed to be there
            try:
                return hashlib.new("sm3", data).digest()
            except ValueError:
                return None

        return None

    def get_size(self) -> Optional[int]:
        return _HASH_SIZE.get(self)

    def __str__(self) -> str:
        return self.value


class Encrypt:
    RSA = 'rsa'
    ECC = 'ecc'
    supported_algorithms = (RSA, ECC)

    @staticmethod
    def is_recognized(algorithm: str) -> bool:
        return algorithm in Encrypt.supported_algorithms


class Sign:
    RSASSA = 'rsassa'
    RSAPSS = 'rsapss'
    ECDSA = 'ecdsa'
    ECDAA = 'ecdaa'
    ECSCHNORR = 'ecschnorr'
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
