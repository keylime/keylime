"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Red Hat, Inc.
"""
import base64
import hashlib
import struct
import unittest
from typing import Union, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey,
    RSAPublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurve,
    EllipticCurvePublicNumbers,
)
import cryptography.hazmat.primitives.asymmetric.ec as crypto_ec
from cryptography.x509 import load_der_x509_certificate

pubkey_type = Union[RSAPublicKey, EllipticCurvePublicKey]


def _pack_in_tpm2b(val):
    return struct.pack(">H", len(val)) + val


# Algorithm constants
TPM2_ALG_NULL = 0x0010

TPM_ECC_NIST_P192 = 0x0001
TPM_ECC_NIST_P224 = 0x0002
TPM_ECC_NIST_P256 = 0x0003
TPM_ECC_NIST_P384 = 0x0004
TPM_ECC_NIST_P521 = 0x0005

TPM_ALG_RSA = 0x0001
TPM_ALG_ECC = 0x0023

TPM_ALG_SHA1 = 0x0004
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C
TPM_ALG_SHA512 = 0x000D

TPM_ALG_AES = 0x0006
TPM_ALG_CFB = 0x0043


# These are the object attribute values important for EK certs
OA_FIXEDTPM = 0x00000002
OA_STCLEAR = 0x00000004
OA_FIXEDPARENT = 0x00000010
OA_SENSITIVEDATAORIGIN = 0x00000020
OA_USERWITHAUTH = 0x00000040
OA_ADMINWITHPOLICY = 0x00000080
OA_NODA = 0x00000400
OA_ENCRYPTEDDUPLICATION = 0x00000800
OA_RESTRICTED = 0x00010000
OA_DECRYPT = 0x00020000
OA_SIGN_ENCRYPT = 0x00040000


# These are some common object attribute values
# Source for AK_EXPECTED_ATTRS: tpm2-tools, tpm2_createak.c, set_key_algorithm
AK_EXPECTED_ATTRS = (
    OA_RESTRICTED
    | OA_USERWITHAUTH
    | OA_SIGN_ENCRYPT
    | OA_FIXEDTPM
    | OA_FIXEDPARENT
    | OA_SENSITIVEDATAORIGIN
)


class NonAsymAlgSpecificParameters():
    sym_algorithm = None
    sym_keybits = None
    sym_mode = None
    sym_details = None
    scheme_scheme = None
    scheme_details = None

    def __init__(self, sym_algorithm, sym_keybits, sym_mode, sym_details, scheme_scheme, scheme_details):
        self.sym_algorithm = sym_algorithm
        self.sym_keybits = sym_keybits
        self.sym_mode = sym_mode
        self.sym_details = sym_details
        self.scheme_scheme = scheme_scheme
        self.scheme_details = scheme_details

    def to_bytes(self):
        sym = struct.pack(
            ">HHH",
            self.sym_algorithm,
            self.sym_keybits,
            self.sym_mode
        )
        scheme = struct.pack(
            ">H",
            self.scheme_scheme
        )
        return sym + scheme


# These values come from "TCG EK Credential Profile For TPM Family 2.0;
#  Level 0, Version 2.3, Revision 2"
EK_LOW_NAMEALG = TPM_ALG_SHA256
EK_HIGH_SHA256_NAMEALG = EK_LOW_NAMEALG
EK_LOW_ATTRIBUTES = (
    OA_FIXEDTPM |
    # ~OA_STCLEAR |
    OA_FIXEDPARENT |
    OA_SENSITIVEDATAORIGIN |
    # ~OA_USERWITHAUTH |
    OA_ADMINWITHPOLICY |
    # ~OA_NODA |
    # ~OA_ENCRYPTEDDUPLICATION |
    OA_RESTRICTED |
    OA_DECRYPT
    # ~OA_SIGN_ENCRYPT,
)
EK_HIGH_ATTRIBUTES = (
    OA_FIXEDTPM |
    # ~OA_STCLEAR |
    OA_FIXEDPARENT |
    OA_SENSITIVEDATAORIGIN |
    OA_USERWITHAUTH |
    OA_ADMINWITHPOLICY |
    # ~OA_NODA |
    # ~OA_ENCRYPTEDDUPLICATION |
    OA_RESTRICTED |
    OA_DECRYPT
    # ~OA_SIGN_ENCRYPT,
)
# TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
EK_LOW_AUTH_POLICY = bytes(
    [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
        0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
        0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
        0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
        0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA,
    ]
)
EK_HIGH_SHA256_AUTH_POLICY = bytes(
    [
        0xCA, 0x3D, 0x0A, 0x99, 0xA2, 0xB9,
        0x39, 0x06, 0xF7, 0xA3, 0x34, 0x24,
        0x14, 0xEF, 0xCF, 0xB3, 0xA3, 0x85,
        0xD4, 0x4C, 0xD1, 0xFD, 0x45, 0x90,
        0x89, 0xD1, 0x9B, 0x50, 0x71, 0xC0,
        0xB7, 0xA0,
    ]
)
EK_LOW_NON_ASYM_ALG_PARMS = NonAsymAlgSpecificParameters(
    TPM_ALG_AES,
    128,
    TPM_ALG_CFB,
    0x00,  # NULL
    TPM2_ALG_NULL,
    0x00,  # NULL
)
EK_HIGH_SHA256_NON_ASYM_ALG_PARMS = EK_LOW_NON_ASYM_ALG_PARMS


def _curve_id_from_name(name: str) -> int:
    if name == "secp192r1":
        return TPM_ECC_NIST_P192
    if name == "secp224r1":
        return TPM_ECC_NIST_P224
    if name == "secp256r1":
        return TPM_ECC_NIST_P256
    if name == "secp384r1":
        return TPM_ECC_NIST_P384
    if name == "secp521r1":
        return TPM_ECC_NIST_P521

    raise ValueError("Invalid curve name %s requested" % name)


def _curve_from_curve_id(cid: int) -> EllipticCurve:
    if cid == TPM_ECC_NIST_P192:
        return crypto_ec.SECP192R1()
    if cid == TPM_ECC_NIST_P224:
        return crypto_ec.SECP224R1()
    if cid == TPM_ECC_NIST_P256:
        return crypto_ec.SECP256R1()
    if cid == TPM_ECC_NIST_P384:
        return crypto_ec.SECP384R1()
    if cid == TPM_ECC_NIST_P521:
        return crypto_ec.SECP521R1()

    raise ValueError("Invalid curve id %d requested" % cid)


def _extract_tpm2b(vals: bytes) -> Tuple[bytes, bytes]:
    (length,) = struct.unpack(">H", vals[0:2])
    # Ignore the length itself when returning
    vals = vals[2:]
    # Return first the currect buffer, and then the rest
    return (vals[:length], vals[length:])


def pubkey_from_tpm2b_public(public: bytes) -> pubkey_type:
    (public, rest) = _extract_tpm2b(public)
    if len(rest) != 0:
        raise ValueError("More in tpm2b_public than tpmt_public")
    # Extract type, [nameAlg], and [objectAttributes] (we don't care about the
    #  latter two)
    (alg_type, _, _) = struct.unpack(">HHI", public[0:8])
    # Ignore the authPolicy
    (_, sym_parms) = _extract_tpm2b(public[8:])
    # Ignore the non-asym-alg parameters
    (sym_mode,) = struct.unpack(">H", sym_parms[0:2])
    # Ignore the sym_mode and keybits (4 bytes), possibly symmetric (2) and sign
    #  scheme (2)
    to_skip = 4 + 2  # sym_mode, keybits and sign scheme
    if sym_mode != TPM2_ALG_NULL:
        to_skip = to_skip + 2
    asym_parms = sym_parms[to_skip:]

    # Handle fields
    if alg_type == TPM_ALG_RSA:
        (keybits, exponent) = struct.unpack(">HI", asym_parms[0:6])
        if exponent == 0:
            exponent = 65537
        (modulus, _) = _extract_tpm2b(asym_parms[6:])
        if (len(modulus) * 8) != keybits:
            raise ValueError(
                "Misparsed either modulus or keybits: %d*8 != %d"
                % (len(modulus), keybits)
            )
        bmodulus = int.from_bytes(modulus, byteorder="big")

        numbers = RSAPublicNumbers(exponent, bmodulus)
        return numbers.public_key(backend=default_backend())

    if alg_type == TPM_ALG_ECC:
        (curve, _) = struct.unpack(">HH", asym_parms[0:4])
        asym_x = asym_parms[4:]
        curve = _curve_from_curve_id(curve)

        (x, asym_y) = _extract_tpm2b(asym_x)
        (y, rest) = _extract_tpm2b(asym_y)
        if len(rest) != 0:
            raise ValueError("Misparsed: more contents after X and Y")

        if (len(x) * 8) != curve.key_size:
            raise ValueError(
                "Misparsed either X or curve: %d*8 != %d" % (
                    len(x), curve.key_size)
            )
        if (len(y) * 8) != curve.key_size:
            raise ValueError(
                "Misparsed either Y or curve curve: %d*8 != %d"
                % (len(y), curve.key_size)
            )

        bx = int.from_bytes(x, byteorder="big")
        by = int.from_bytes(y, byteorder="big")

        numbers = EllipticCurvePublicNumbers(bx, by, curve)
        return numbers.public_key(backend=default_backend())

    raise ValueError("Invalid tpm2b_public type: %d" % alg_type)


def tpm2b_public_from_pubkey(pubkey: pubkey_type, name_alg: int, attributes: int, auth_policy: bytes, parms: NonAsymAlgSpecificParameters) -> bytes:
    """
    Returns a reconstructed TPM2B_PUBLIC from a public key.
    """
    if isinstance(pubkey, RSAPublicKey):
        alg_type = TPM_ALG_RSA

        numbers = pubkey.public_numbers()
        n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8,
                               byteorder="big")

        pub_e = numbers.e
        if pub_e == 65537:
            pub_e = 0

        algo_parms = struct.pack(">HI", pubkey.key_size, pub_e)
        unique = _pack_in_tpm2b(n)
    elif isinstance(pubkey, EllipticCurvePublicKey):
        alg_type = TPM_ALG_ECC

        numbers = pubkey.public_numbers()

        algo_parms = struct.pack(
            ">HH",
            _curve_id_from_name(numbers.curve.name),
            TPM2_ALG_NULL,
        )
        unique_x = numbers.x.to_bytes(
            (numbers.x.bit_length() + 7) // 8, byteorder="big"
        )
        unique_y = numbers.y.to_bytes(
            (numbers.y.bit_length() + 7) // 8, byteorder="big"
        )
        unique = _pack_in_tpm2b(unique_x) + _pack_in_tpm2b(unique_y)
    else:
        raise ValueError("Unsupported public key type")

    auth_policy = _pack_in_tpm2b(auth_policy)
    parameters = parms.to_bytes() + algo_parms

    tpmt_pub = (
        struct.pack(
            ">HHI",
            alg_type,
            name_alg,
            attributes,
        )
        + auth_policy
        + parameters
        + unique
    )
    return _pack_in_tpm2b(tpmt_pub)


def _get_hasher_from_name_alg(nameAlg: int):
    if nameAlg == TPM_ALG_SHA1:
        return hashlib.sha1()
    if nameAlg == TPM_ALG_SHA256:
        return hashlib.sha256()
    if nameAlg == TPM_ALG_SHA384:
        return hashlib.sha384()
    if nameAlg == TPM_ALG_SHA512:
        return hashlib.sha512()

    raise ValueError("Unsupported nameAlg %s used" % nameAlg)


def get_tpm2b_public_object_attributes(public: bytes) -> int:
    # Ignore length, type, namealg and get attributes
    (
        _,
        _,
        _,
        attrs,
    ) = struct.unpack(">HHHI", public[0:10])
    return attrs


def get_tpm2b_public_name(public: bytes) -> str:
    """
    Return the TPM name of an object provided as TPM2B_PUBLIC.

    The name is equal to: nameAlg || H(T_Public)
    where
        H is the hash function identified by nameAlg
        T_Public is the TPMT_PUBLIC part of the object
    """
    # We get a TPM2B_PUBLIC, but don't care about the buffer portion.
    # Thus we drop the first two bytes (the uint16 size)
    (tpmt_public, rest) = _extract_tpm2b(public)
    if len(rest) != 0:
        raise ValueError("Invalid tpm2b_public")
    # The first two bytes are type, those are not critical for computing the
    # of Name other than that they are used in the computation.
    # Next two are nameAlg, which are critical.
    (nameAlg,) = struct.unpack(">H", tpmt_public[2:4])
    # Compute the H(TPMT_Public) portion
    hasher = _get_hasher_from_name_alg(int(nameAlg))
    hasher.update(tpmt_public)
    # The name is nameAlg || H(TP_PUBLIC)
    name = tpmt_public[2:4] + hasher.digest()
    # We return it as hex-encoded, since that's the way we pass it onwards
    return name.hex()


def object_attributes_description(oas: int) -> str:
    attrs = []
    if (oas & OA_FIXEDTPM) != 0:
        attrs.append("fixed-tpm")
    if (oas & OA_STCLEAR) != 0:
        attrs.append("st-clear")
    if (oas & OA_FIXEDPARENT) != 0:
        attrs.append("fixed-parent")
    if (oas & OA_SENSITIVEDATAORIGIN) != 0:
        attrs.append("sensitive-data-origin")
    if (oas & OA_USERWITHAUTH) != 0:
        attrs.append("user-with-auth")
    if (oas & OA_ADMINWITHPOLICY) != 0:
        attrs.append("admin-with-policy")
    if (oas & OA_NODA) != 0:
        attrs.append("no-da")
    if (oas & OA_ENCRYPTEDDUPLICATION) != 0:
        attrs.append("encrypted-duplication")
    if (oas & OA_RESTRICTED) != 0:
        attrs.append("restricted")
    if (oas & OA_DECRYPT) != 0:
        attrs.append("decrypt")
    if (oas & OA_SIGN_ENCRYPT) != 0:
        attrs.append("sign-encrypt")

    return " | ".join(attrs)


def ek_low_tpm2b_public_from_pubkey(pubkey: pubkey_type) -> bytes:
    return tpm2b_public_from_pubkey(
        pubkey,
        EK_LOW_NAMEALG,
        EK_LOW_ATTRIBUTES,
        EK_LOW_AUTH_POLICY,
        EK_LOW_NON_ASYM_ALG_PARMS,
    )


class TestTpm2Objects(unittest.TestCase):
    def test_get_tpm2b_public_name(self):
        test_pub = base64.b64decode(
            "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDJBIF+SxeEt8TAwcnMZIvJWs3luBARcI"
            "HXC7I/XH7ZXbwLyispm/tpvhRw0w60JbwF4om1LbApQbG9cWR7AOi3ykv5bOgszsIG"
            "DOYJNfWuylW2uQBvMPEeF+ysrCjFTl5HOhXEpaz+E//juoKS2Jh9zYr2kt8rnGAJyj"
            "a10LUsYNt4h6eyeLVrsZIckkKP4tZwPOokfdX+6YCtGy5Y1buTvBSGNWa+VGo6hZVD"
            "649mg6EHyv0geSHXojx0Iqjsl/NQXzOCvyuaf6CBu9pkiIZCePlrl2uD1tXEdX0ipB"
            "B9Fppc/5cJQ2NyJOuvi4MUK5y38QpwnZwd4Utr2WdyEPoF"
        )
        test_pub_correct_name = (
            "000b347dbfebe5bdbc55f6782a3cba91610f9d1b554a1aef07b4db28cf36da9390"
            "09"
        )
        new_name = get_tpm2b_public_name(test_pub)
        self.assertEqual(new_name, test_pub_correct_name)

    def test_get_tpm2b_public_object_attributes(self):
        test_pub = base64.b64decode(
            "ARgAAQALAAUAcgAAABAAFAALCAAAAAAAAQDJBIF+SxeEt8TAwcnMZIvJWs3luBARcI"
            "HXC7I/XH7ZXbwLyispm/tpvhRw0w60JbwF4om1LbApQbG9cWR7AOi3ykv5bOgszsIG"
            "DOYJNfWuylW2uQBvMPEeF+ysrCjFTl5HOhXEpaz+E//juoKS2Jh9zYr2kt8rnGAJyj"
            "a10LUsYNt4h6eyeLVrsZIckkKP4tZwPOokfdX+6YCtGy5Y1buTvBSGNWa+VGo6hZVD"
            "649mg6EHyv0geSHXojx0Iqjsl/NQXzOCvyuaf6CBu9pkiIZCePlrl2uD1tXEdX0ipB"
            "B9Fppc/5cJQ2NyJOuvi4MUK5y38QpwnZwd4Utr2WdyEPoF"
        )
        expected_attributes = (
            OA_RESTRICTED
            | OA_USERWITHAUTH
            | OA_SIGN_ENCRYPT
            | OA_FIXEDTPM
            | OA_FIXEDPARENT
            | OA_SENSITIVEDATAORIGIN
        )
        new_attributes = get_tpm2b_public_object_attributes(test_pub)
        self.assertEqual(new_attributes, expected_attributes)

    # Testing tpm2b_public_from_pubkey
    # These example certificates were standard EK certificates from a valid TPM,
    #  so these fields are selected according to
    #  TCG EK Credential Profile For TPM Family 2.0
    #  Level 0, Version 2.3, Revision 2"
    # Both are from the Low Ranges
    # The RSA set is according to Template L-1, section B.3.3
    # The EC set is according to Template L-2, section B.3.4

    def test_tpm2b_public_from_pubkey_rsa(self):
        test_rsa_cert = base64.b64decode(
            "MIIEnDCCA4SgAwIBAgIEL8wtHjANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCRE"
            "UxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BU"
            "SUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE"
            "1hbnVmYWN0dXJpbmcgQ0EgMDM1MB4XDTE4MDMwMTE0MTkzM1oXDTMzMDMwMTE0MTkz"
            "M1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALaIriXJCSUKdvWRDY"
            "dRbtdTK8i7eCJwHV8NhQ8Cor8NKoVmrnOdDhGqXlrKyJTueA9D2P4yQlWZI+tD9PCV"
            "CHCQiGmqxxHQXgzCzx6z+57HTUNPDi16K6ZFPNs3UkhAQxeGLOy36XD35zpfgadtvc"
            "lxJC8L+UgKfXVAM3/oMj4cDXa4cbVKhlfIQXD9OhcNjvESPWVFw0dj7Q6HM0jEkezM"
            "ew5sJ3I+LET1cIIhUlXvX8fWLu2MHx9+6LIBjkN8SuMLjKBQZjh+rEbHoFuG7Ib9pN"
            "ucrPAycid4EBBQB65j9irZ8C+ZdUUkKM5hsDhcenm/0AdfqAGXsFtsEa8DuDECAwEA"
            "AaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS"
            "5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMzUvT3B0aWdhUnNhTWZyQ0EwMzUu"
            "Y3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDA"
            "tpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUC"
            "AwwHaWQ6MDczZjAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly"
            "9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDM1L09wdGlnYVJzYU1mckNB"
            "MDM1LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFM53FTtuEQ"
            "ykrilxoJhR70mTJiAqMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EF"
            "AhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAIJ7pvW3yj2wAHO1fq"
            "zOeKg/xQjBMZ2hdpqVmhc+gU7F7zCMF85iWodISkThp9aa6p7VptkNcp5BNE1ojx+3"
            "1aJZRAFTCV0b0QxKXELTVsQLvBVmKGtFuaP3FPDVJYIOnQtb8uF+2LduF5P9K6oXdF"
            "TFuh1kG8GU/UUnltA7h6u2qhnj5uvFEDz7pxX1lt/GbI1nTYB+0SYtveIglpFyZK71"
            "0FH9UAvvR8byEbK+adE+teBUOexdXhTC1ZmPZmTvHSqmeRV3UTZFZRnyOTBnN8QlN0"
            "pMVmwFTak931PqxV0xOSXkMcvTre39jzkhEJ+VMb5EOMFfsVn+b4snob9jank="
        )
        correct_rsa_obj = base64.b64decode(
            "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAE"
            "MAEAgAAAAAAAEAtoiuJckJJQp29ZENh1Fu11MryLt4InAdXw2FDwKivw0qhWauc50O"
            "EapeWsrIlO54D0PY/jJCVZkj60P08JUIcJCIaarHEdBeDMLPHrP7nsdNQ08OLXorpk"
            "U82zdSSEBDF4Ys7LfpcPfnOl+Bp229yXEkLwv5SAp9dUAzf+gyPhwNdrhxtUqGV8hB"
            "cP06Fw2O8RI9ZUXDR2PtDoczSMSR7Mx7Dmwncj4sRPVwgiFSVe9fx9Yu7YwfH37osg"
            "GOQ3xK4wuMoFBmOH6sRsegW4bshv2k25ys8DJyJ3gQEFAHrmP2KtnwL5l1RSQozmGw"
            "OFx6eb/QB1+oAZewW2wRrwO4MQ=="
        )
        test_rsa_cert = load_der_x509_certificate(
            test_rsa_cert, backend=default_backend()
        )
        new_rsa_obj = ek_low_tpm2b_public_from_pubkey(
            test_rsa_cert.public_key()
        )
        self.assertEqual(new_rsa_obj.hex(), correct_rsa_obj.hex())

    def test_tpm2b_public_from_pubkey_ec(self):
        test_ec_cert = base64.b64decode(
            "MIIDEDCCAragAwIBAgIEcYSJiTAKBggqhkjOPQQDAjCBgzELMAkGA1UEBhMCREUxIT"
            "AfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdB"
            "KFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgRUNDIE1hbn"
            "VmYWN0dXJpbmcgQ0EgMDM1MB4XDTE4MDMwMTE0MTkxNloXDTMzMDMwMTE0MTkxNlow"
            "ADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNK9AtBnW5bwNG2ZIWDrM8w/h03Ht2"
            "lp3MUosV05DeBHWZEZfmKsHMBqpqDsIKkEgclQawA4BFR5YUvSdrSUDTGjggGYMIIB"
            "lDBbBggrBgEFBQcBAQRPME0wSwYIKwYBBQUHMAKGP2h0dHA6Ly9wa2kuaW5maW5lb2"
            "4uY29tL09wdGlnYUVjY01mckNBMDM1L09wdGlnYUVjY01mckNBMDM1LmNydDAOBgNV"
            "HQ8BAf8EBAMCAAgwWAYDVR0RAQH/BE4wTKRKMEgxFjAUBgVngQUCAQwLaWQ6NDk0Nj"
            "U4MDAxGjAYBgVngQUCAgwPU0xCIDk2NzAgVFBNMi4wMRIwEAYFZ4EFAgMMB2lkOjA3"
            "M2YwDAYDVR0TAQH/BAIwADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vcGtpLmluZm"
            "luZW9uLmNvbS9PcHRpZ2FFY2NNZnJDQTAzNS9PcHRpZ2FFY2NNZnJDQTAzNS5jcmww"
            "FQYDVR0gBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBQ2WY8i7ITDxPZA0hwWfQ"
            "uRE3uQpDAQBgNVHSUECTAHBgVngQUIATAhBgNVHQkEGjAYMBYGBWeBBQIQMQ0wCwwD"
            "Mi4wAgEAAgF0MAoGCCqGSM49BAMCA0gAMEUCIQCdCv3+G+KsM4OiT3SgKqvE8r5ktD"
            "I5elC9xTmS9mDA3AIgcckalMvQVTst1pGMEyAI+OoXTnYA1sBRm27WJ6sZag8="
        )
        correct_ec_obj = base64.b64decode(
            "AHoAIwALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAE"
            "MAEAADABAAINK9AtBnW5bwNG2ZIWDrM8w/h03Ht2lp3MUosV05DeBHACBZkRl+Yqwc"
            "wGqmoOwgqQSByVBrADgEVHlhS9J2tJQNMQ=="
        )
        test_ec_cert = load_der_x509_certificate(
            test_ec_cert, backend=default_backend()
        )
        new_ec_obj = ek_low_tpm2b_public_from_pubkey(test_ec_cert.public_key())
        self.assertEqual(new_ec_obj.hex(), correct_ec_obj.hex())

    def test_pubkey_from_tpm2b_public_rsa(self):
        test_rsa_cert = base64.b64decode(
            "MIIEnDCCA4SgAwIBAgIEL8wtHjANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCRE"
            "UxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BU"
            "SUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgUlNBIE"
            "1hbnVmYWN0dXJpbmcgQ0EgMDM1MB4XDTE4MDMwMTE0MTkzM1oXDTMzMDMwMTE0MTkz"
            "M1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALaIriXJCSUKdvWRDY"
            "dRbtdTK8i7eCJwHV8NhQ8Cor8NKoVmrnOdDhGqXlrKyJTueA9D2P4yQlWZI+tD9PCV"
            "CHCQiGmqxxHQXgzCzx6z+57HTUNPDi16K6ZFPNs3UkhAQxeGLOy36XD35zpfgadtvc"
            "lxJC8L+UgKfXVAM3/oMj4cDXa4cbVKhlfIQXD9OhcNjvESPWVFw0dj7Q6HM0jEkezM"
            "ew5sJ3I+LET1cIIhUlXvX8fWLu2MHx9+6LIBjkN8SuMLjKBQZjh+rEbHoFuG7Ib9pN"
            "ucrPAycid4EBBQB65j9irZ8C+ZdUUkKM5hsDhcenm/0AdfqAGXsFtsEa8DuDECAwEA"
            "AaOCAZgwggGUMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEFBQcwAoY/aHR0cDovL3BraS"
            "5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMzUvT3B0aWdhUnNhTWZyQ0EwMzUu"
            "Y3J0MA4GA1UdDwEB/wQEAwIAIDBYBgNVHREBAf8ETjBMpEowSDEWMBQGBWeBBQIBDA"
            "tpZDo0OTQ2NTgwMDEaMBgGBWeBBQICDA9TTEIgOTY3MCBUUE0yLjAxEjAQBgVngQUC"
            "AwwHaWQ6MDczZjAMBgNVHRMBAf8EAjAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6Ly"
            "9wa2kuaW5maW5lb24uY29tL09wdGlnYVJzYU1mckNBMDM1L09wdGlnYVJzYU1mckNB"
            "MDM1LmNybDAVBgNVHSAEDjAMMAoGCCqCFABEARQBMB8GA1UdIwQYMBaAFM53FTtuEQ"
            "ykrilxoJhR70mTJiAqMBAGA1UdJQQJMAcGBWeBBQgBMCEGA1UdCQQaMBgwFgYFZ4EF"
            "AhAxDTALDAMyLjACAQACAXQwDQYJKoZIhvcNAQELBQADggEBAIJ7pvW3yj2wAHO1fq"
            "zOeKg/xQjBMZ2hdpqVmhc+gU7F7zCMF85iWodISkThp9aa6p7VptkNcp5BNE1ojx+3"
            "1aJZRAFTCV0b0QxKXELTVsQLvBVmKGtFuaP3FPDVJYIOnQtb8uF+2LduF5P9K6oXdF"
            "TFuh1kG8GU/UUnltA7h6u2qhnj5uvFEDz7pxX1lt/GbI1nTYB+0SYtveIglpFyZK71"
            "0FH9UAvvR8byEbK+adE+teBUOexdXhTC1ZmPZmTvHSqmeRV3UTZFZRnyOTBnN8QlN0"
            "pMVmwFTak931PqxV0xOSXkMcvTre39jzkhEJ+VMb5EOMFfsVn+b4snob9jank="
        )
        test_rsa_cert = load_der_x509_certificate(
            test_rsa_cert, backend=default_backend()
        )
        correct_rsa_obj = base64.b64decode(
            "AToAAQALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAE"
            "MAEAgAAAAAAAEAtoiuJckJJQp29ZENh1Fu11MryLt4InAdXw2FDwKivw0qhWauc50O"
            "EapeWsrIlO54D0PY/jJCVZkj60P08JUIcJCIaarHEdBeDMLPHrP7nsdNQ08OLXorpk"
            "U82zdSSEBDF4Ys7LfpcPfnOl+Bp229yXEkLwv5SAp9dUAzf+gyPhwNdrhxtUqGV8hB"
            "cP06Fw2O8RI9ZUXDR2PtDoczSMSR7Mx7Dmwncj4sRPVwgiFSVe9fx9Yu7YwfH37osg"
            "GOQ3xK4wuMoFBmOH6sRsegW4bshv2k25ys8DJyJ3gQEFAHrmP2KtnwL5l1RSQozmGw"
            "OFx6eb/QB1+oAZewW2wRrwO4MQ=="
        )
        new_rsa_pubkey = pubkey_from_tpm2b_public(correct_rsa_obj)
        correct_rsa_pubkey = test_rsa_cert.public_key()
        new_rsa_pubkey_n = new_rsa_pubkey.public_numbers()
        correct_rsa_pubkey_n = correct_rsa_pubkey.public_numbers()
        self.assertEqual(new_rsa_pubkey.key_size, correct_rsa_pubkey.key_size)
        self.assertEqual(new_rsa_pubkey_n.e, correct_rsa_pubkey_n.e)
        self.assertEqual(new_rsa_pubkey_n.n, correct_rsa_pubkey_n.n)

    def test_pubkey_from_tpm2b_public_rsa_without_encryption(self):
        new_rsa_pubkey = pubkey_from_tpm2b_public(
            bytes.fromhex(
                "01180001000b00050072000000100014000b0800000000000100cac43903c6"
                "16bba049ce413c961c901b56181392c7999e672e6e5ecdd7a625d4702c3d78"
                "deac81e1372b0ca1894ac0f16add636bb53d3d5b112d8f3b169ccadef6bac0"
                "d909067d1ff81dae34b26cd538a52fa20ee7bbf3b16214417d35bde80cbb0f"
                "1b3267fd6211ecfb652f771f7eaeff560b91ef2f374ab1d37bba5a7a1c7cd4"
                "4961cdd7351ee060947f43244f45fc42ea6a1ea783aaa18dc8cce90d9a97f8"
                "da09e72637a0167fdbf4cc0d09f2f752d864d45bd34ed387acc0bcddca26c6"
                "1ebe9056013a35cd1d8011336af93579afa424fe50fd7e2b03270518505710"
                "82fcae891e2897e3117fd28bd03d2d2ffdfcfa0ff95f76af9383e3c9e59fe4"
                "dde753"
            )
        )
        new_rsa_pubkey_n = new_rsa_pubkey.public_numbers()

        self.assertEqual(new_rsa_pubkey.key_size, 2048)
        self.assertEqual(new_rsa_pubkey_n.e, 65537)
        self.assertEqual(
            str(new_rsa_pubkey_n.n),
            "255968986296679270326283402717529063492526907681140893873754141432"
            "890531031973586937300971300465026177966018575012122367284728088154"
            "485873651193407172159946655006581809152369460009001515677703036255"
            "837234635576083087037905135410736640524495731191518154258439490758"
            "531740360767515943902821573272461751306668217217601399605319344343"
            "524504419559281243744525835687758392857402638332592577865592671234"
            "679107983328133731582503713366603521336278457142403979969779706740"
            "010077961630324526931687863526905140593203113247551679416434551326"
            "587069716966112452602019925398408142602185862884082705845069125895"
            "71106286823536420841299",
        )

    def test_pubkey_from_tpm2b_public_ec(self):
        test_ec_cert = base64.b64decode(
            "MIIDEDCCAragAwIBAgIEcYSJiTAKBggqhkjOPQQDAjCBgzELMAkGA1UEBhMCREUxIT"
            "AfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwRT1BUSUdB"
            "KFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkgRUNDIE1hbn"
            "VmYWN0dXJpbmcgQ0EgMDM1MB4XDTE4MDMwMTE0MTkxNloXDTMzMDMwMTE0MTkxNlow"
            "ADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNK9AtBnW5bwNG2ZIWDrM8w/h03Ht2"
            "lp3MUosV05DeBHWZEZfmKsHMBqpqDsIKkEgclQawA4BFR5YUvSdrSUDTGjggGYMIIB"
            "lDBbBggrBgEFBQcBAQRPME0wSwYIKwYBBQUHMAKGP2h0dHA6Ly9wa2kuaW5maW5lb2"
            "4uY29tL09wdGlnYUVjY01mckNBMDM1L09wdGlnYUVjY01mckNBMDM1LmNydDAOBgNV"
            "HQ8BAf8EBAMCAAgwWAYDVR0RAQH/BE4wTKRKMEgxFjAUBgVngQUCAQwLaWQ6NDk0Nj"
            "U4MDAxGjAYBgVngQUCAgwPU0xCIDk2NzAgVFBNMi4wMRIwEAYFZ4EFAgMMB2lkOjA3"
            "M2YwDAYDVR0TAQH/BAIwADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vcGtpLmluZm"
            "luZW9uLmNvbS9PcHRpZ2FFY2NNZnJDQTAzNS9PcHRpZ2FFY2NNZnJDQTAzNS5jcmww"
            "FQYDVR0gBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBQ2WY8i7ITDxPZA0hwWfQ"
            "uRE3uQpDAQBgNVHSUECTAHBgVngQUIATAhBgNVHQkEGjAYMBYGBWeBBQIQMQ0wCwwD"
            "Mi4wAgEAAgF0MAoGCCqGSM49BAMCA0gAMEUCIQCdCv3+G+KsM4OiT3SgKqvE8r5ktD"
            "I5elC9xTmS9mDA3AIgcckalMvQVTst1pGMEyAI+OoXTnYA1sBRm27WJ6sZag8="
        )
        correct_ec_obj = base64.b64decode(
            "AHoAIwALAAMAsgAgg3GXZ0SEs/gakMyNRqXXJP1S124GUgtk8qHaGzMUaaoABgCAAE"
            "MAEAADABAAINK9AtBnW5bwNG2ZIWDrM8w/h03Ht2lp3MUosV05DeBHACBZkRl+Yqwc"
            "wGqmoOwgqQSByVBrADgEVHlhS9J2tJQNMQ=="
        )
        test_ec_cert = load_der_x509_certificate(
            test_ec_cert, backend=default_backend()
        )
        new_ec_pubkey = pubkey_from_tpm2b_public(correct_ec_obj)
        correct_ec_pubkey = test_ec_cert.public_key()
        new_ec_pubkey_n = new_ec_pubkey.public_numbers()
        correct_ec_pubkey_n = correct_ec_pubkey.public_numbers()
        self.assertEqual(
            new_ec_pubkey_n.curve.name,
            correct_ec_pubkey_n.curve.name
        )
        self.assertEqual(new_ec_pubkey_n.x, correct_ec_pubkey_n.x)
        self.assertEqual(new_ec_pubkey_n.y, correct_ec_pubkey_n.y)

    def test_pubkey_from_tpm2b_public_ec_without_encryption(self):
        new_ec_pubkey = pubkey_from_tpm2b_public(
            bytes.fromhex(
                "00580023000b00050072000000100018000b000300100020c74568135840f4"
                "97ad575ebeabe6d01f3f098b5a768111ab423d5f26b259a4f000205ec0f586"
                "b53e348bc916b43a015e6ceefd947d685e59ff65357499f2c4788cba"
            )
        )
        new_ec_pubkey_n = new_ec_pubkey.public_numbers()

        self.assertEqual(new_ec_pubkey_n.curve.name, "secp256r1")
        self.assertEqual(
            str(new_ec_pubkey_n.x),
            "901328876186929754842544537316510944104832864446891914011641755043"
            "34705501424",
        )
        self.assertEqual(
            str(new_ec_pubkey_n.y),
            "428583369628394219355595706223697775291854911504755996137787899503"
            "32157332666",
        )

    def test_object_attributes_description(self):
        with self.subTest(attrs="sign-encrypt"):
            val = object_attributes_description((OA_SIGN_ENCRYPT))
            self.assertEqual(val, "sign-encrypt")

        with self.subTest(attrs="<empty>"):
            val = object_attributes_description((0))
            self.assertEqual(val, "")

        with self.subTest(attrs="<all>"):
            val = object_attributes_description(
                (
                    OA_FIXEDTPM
                    | OA_STCLEAR
                    | OA_FIXEDPARENT
                    | OA_SENSITIVEDATAORIGIN
                    | OA_USERWITHAUTH
                    | OA_ADMINWITHPOLICY
                    | OA_NODA
                    | OA_ENCRYPTEDDUPLICATION
                    | OA_RESTRICTED
                    | OA_DECRYPT
                    | OA_SIGN_ENCRYPT
                )
            )
            self.assertEqual(
                val,
                "fixed-tpm | st-clear | fixed-parent | sensitive-data-origin | "
                "user-with-auth | admin-with-policy | no-da | "
                "encrypted-duplication | restricted | decrypt | sign-encrypt",
            )


if __name__ == "__main__":
    unittest.main()
