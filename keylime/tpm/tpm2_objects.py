import hashlib
import struct
from typing import Any, Tuple, Union, cast

import cryptography.hazmat.primitives.asymmetric.ec as crypto_ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurve,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers

pubkey_type = Union[RSAPublicKey, EllipticCurvePublicKey]


def _pack_in_tpm2b(val: bytes) -> bytes:
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
    OA_RESTRICTED | OA_USERWITHAUTH | OA_SIGN_ENCRYPT | OA_FIXEDTPM | OA_FIXEDPARENT | OA_SENSITIVEDATAORIGIN
)


class NonAsymAlgSpecificParameters:
    sym_algorithm: int
    sym_keybits: int
    sym_mode: int
    sym_details: int
    scheme_scheme: int
    scheme_details: int

    def __init__(
        self,
        sym_algorithm: int,
        sym_keybits: int,
        sym_mode: int,
        sym_details: int,
        scheme_scheme: int,
        scheme_details: int,
    ) -> None:
        self.sym_algorithm = sym_algorithm
        self.sym_keybits = sym_keybits
        self.sym_mode = sym_mode
        self.sym_details = sym_details
        self.scheme_scheme = scheme_scheme
        self.scheme_details = scheme_details

    def to_bytes(self) -> bytes:
        sym = struct.pack(">HHH", self.sym_algorithm, self.sym_keybits, self.sym_mode)
        scheme = struct.pack(">H", self.scheme_scheme)
        return sym + scheme


# These values come from "TCG EK Credential Profile For TPM Family 2.0;
#  Level 0, Version 2.3, Revision 2"
EK_LOW_NAMEALG = TPM_ALG_SHA256
EK_HIGH_SHA256_NAMEALG = EK_LOW_NAMEALG
EK_LOW_ATTRIBUTES = (
    OA_FIXEDTPM
    |
    # ~OA_STCLEAR |
    OA_FIXEDPARENT
    | OA_SENSITIVEDATAORIGIN
    |
    # ~OA_USERWITHAUTH |
    OA_ADMINWITHPOLICY
    |
    # ~OA_NODA |
    # ~OA_ENCRYPTEDDUPLICATION |
    OA_RESTRICTED
    | OA_DECRYPT
    # ~OA_SIGN_ENCRYPT,
)
EK_HIGH_ATTRIBUTES = (
    OA_FIXEDTPM
    |
    # ~OA_STCLEAR |
    OA_FIXEDPARENT
    | OA_SENSITIVEDATAORIGIN
    | OA_USERWITHAUTH
    | OA_ADMINWITHPOLICY
    |
    # ~OA_NODA |
    # ~OA_ENCRYPTEDDUPLICATION |
    OA_RESTRICTED
    | OA_DECRYPT
    # ~OA_SIGN_ENCRYPT,
)
# TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
EK_LOW_AUTH_POLICY = bytes(
    [
        0x83,
        0x71,
        0x97,
        0x67,
        0x44,
        0x84,
        0xB3,
        0xF8,
        0x1A,
        0x90,
        0xCC,
        0x8D,
        0x46,
        0xA5,
        0xD7,
        0x24,
        0xFD,
        0x52,
        0xD7,
        0x6E,
        0x06,
        0x52,
        0x0B,
        0x64,
        0xF2,
        0xA1,
        0xDA,
        0x1B,
        0x33,
        0x14,
        0x69,
        0xAA,
    ]
)
EK_HIGH_SHA256_AUTH_POLICY = bytes(
    [
        0xCA,
        0x3D,
        0x0A,
        0x99,
        0xA2,
        0xB9,
        0x39,
        0x06,
        0xF7,
        0xA3,
        0x34,
        0x24,
        0x14,
        0xEF,
        0xCF,
        0xB3,
        0xA3,
        0x85,
        0xD4,
        0x4C,
        0xD1,
        0xFD,
        0x45,
        0x90,
        0x89,
        0xD1,
        0x9B,
        0x50,
        0x71,
        0xC0,
        0xB7,
        0xA0,
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

    raise ValueError(f"Invalid curve name {name} requested")


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

    raise ValueError(f"Invalid curve id {cid} requested")


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
            raise ValueError(f"Misparsed either modulus or keybits: {len(modulus)}*8 != {keybits}")
        bmodulus = int.from_bytes(modulus, byteorder="big")

        rsa_numbers = RSAPublicNumbers(exponent, bmodulus)
        return rsa_numbers.public_key(backend=default_backend())

    if alg_type == TPM_ALG_ECC:
        (curve_id, _) = struct.unpack(">HH", asym_parms[0:4])
        asym_x = asym_parms[4:]
        curve = _curve_from_curve_id(curve_id)

        (x, asym_y) = _extract_tpm2b(asym_x)
        (y, rest) = _extract_tpm2b(asym_y)
        if len(rest) != 0:
            raise ValueError("Misparsed: more contents after X and Y")

        if (len(x) * 8) != curve.key_size:
            raise ValueError(f"Misparsed either X or curve: {len(x)}*8 != {curve.key_size}")
        if (len(y) * 8) != curve.key_size:
            raise ValueError(f"Misparsed either Y or curve curve: {len(y)}*8 != {curve.key_size}")

        bx = int.from_bytes(x, byteorder="big")
        by = int.from_bytes(y, byteorder="big")

        ecc_numbers = EllipticCurvePublicNumbers(bx, by, curve)
        return ecc_numbers.public_key(backend=default_backend())

    raise ValueError(f"Invalid tpm2b_public type: {alg_type}")


def tpm2b_public_from_pubkey(
    pubkey: pubkey_type, name_alg: int, attributes: int, auth_policy: bytes, parms: NonAsymAlgSpecificParameters
) -> bytes:
    """
    Returns a reconstructed TPM2B_PUBLIC from a public key.
    """
    if isinstance(pubkey, RSAPublicKey):
        alg_type = TPM_ALG_RSA

        rsa_numbers = pubkey.public_numbers()
        n = rsa_numbers.n.to_bytes((rsa_numbers.n.bit_length() + 7) // 8, byteorder="big")

        pub_e = rsa_numbers.e
        if pub_e == 65537:
            pub_e = 0

        algo_parms = struct.pack(">HI", pubkey.key_size, pub_e)
        unique = _pack_in_tpm2b(n)
    elif isinstance(pubkey, EllipticCurvePublicKey):
        alg_type = TPM_ALG_ECC

        ecc_numbers = pubkey.public_numbers()

        algo_parms = struct.pack(
            ">HH",
            _curve_id_from_name(ecc_numbers.curve.name),
            TPM2_ALG_NULL,
        )
        unique_x = ecc_numbers.x.to_bytes((ecc_numbers.x.bit_length() + 7) // 8, byteorder="big")
        unique_y = ecc_numbers.y.to_bytes((ecc_numbers.y.bit_length() + 7) // 8, byteorder="big")
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


def _get_hasher_from_name_alg(nameAlg: int) -> Any:
    if nameAlg == TPM_ALG_SHA1:
        return hashlib.sha1()
    if nameAlg == TPM_ALG_SHA256:
        return hashlib.sha256()
    if nameAlg == TPM_ALG_SHA384:
        return hashlib.sha384()
    if nameAlg == TPM_ALG_SHA512:
        return hashlib.sha512()

    raise ValueError(f"Unsupported nameAlg {nameAlg} used")


def get_tpm2b_public_object_attributes(public: bytes) -> int:
    # Ignore length, type, namealg and get attributes
    (
        _,
        _,
        _,
        attrs,
    ) = struct.unpack(">HHHI", public[0:10])
    return cast(int, attrs)


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
    return cast(str, name.hex())


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
