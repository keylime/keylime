"""
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Kaifeng Wang
"""


def is_accepted(algorithm, accepted):
    """Check whether algorithm is accepted

    @param algorithm: algorithm to be checked
    @param accepted: a list of acceptable algorithms
    """
    return algorithm in accepted


class Hash:
    SHA1 = 'sha1'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    SM3_256 = 'sm3_256'
    supported_algorithms = (SHA1, SHA256, SHA384, SHA512, SM3_256)

    @staticmethod
    def is_recognized(algorithm):
        return algorithm in Hash.supported_algorithms


class Encrypt:
    RSA = 'rsa'
    ECC = 'ecc'
    supported_algorithms = (RSA, ECC)

    @staticmethod
    def is_recognized(algorithm):
        return algorithm in Encrypt.supported_algorithms


class Sign:
    RSASSA = 'rsassa'
    RSAPSS = 'rsapss'
    ECDSA = 'ecdsa'
    ECDAA = 'ecdaa'
    ECSCHNORR = 'ecschnorr'
    supported_algorithms = (RSASSA, RSAPSS, ECDSA, ECDAA, ECSCHNORR)

    @staticmethod
    def is_recognized(algorithm):
        return algorithm in Sign.supported_algorithms


_HASH_SIZE = {
    Hash.SHA1: 160,
    Hash.SHA256: 256,
    Hash.SHA384: 384,
    Hash.SHA512: 512,
}


def get_hash_size(algorithm):
    return _HASH_SIZE.get(algorithm, 0)
