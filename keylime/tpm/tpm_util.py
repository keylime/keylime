# Some of the functions in this file were adapted from Microsoft's TPM 2
# reference implementation that states the following:
#
# Microsoft Reference Implementation for TPM 2.0
#
#  The copyright in this software is being made available under the BSD License,
#  included below. This software may be subject to other third party and
#  contributor rights, including patent rights, and no such rights are granted
#  under this license.
#
#  Copyright (c) Microsoft Corporation
#
#  All rights reserved.
#
#  BSD License
#
#  Redistribution and use in source and binary forms, with or without modification,
#  are permitted provided that the following conditions are met:
#
#  Redistributions of source code must retain the above copyright notice, this list
#  of conditions and the following disclaimer.
#
#  Redistributions in binary form must reproduce the above copyright notice, this
#  list of conditions and the following disclaimer in the documentation and/or
#  other materials provided with the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
#  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
#  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import binascii
import os
import string
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode

from keylime import config, crypto, json, keylime_logging
from keylime.tpm import tpm2_objects

logger = keylime_logging.init_logging("tpm_util")

SupportedKeyTypes = Union[RSAPublicKey, EllipticCurvePublicKey]


def verify(
    pubkey: SupportedKeyTypes,
    sig: bytes,
    digest: bytes,
    hashfunc: hashes.HashAlgorithm,
    sigalg: int = tpm2_objects.TPM_ALG_RSASSA,
    saltlen: int = 0,
) -> None:
    """Do signature verification with the given public key"""
    if isinstance(pubkey, RSAPublicKey):
        if sigalg == tpm2_objects.TPM_ALG_RSAPSS:
            pubkey.verify(
                sig, digest, padding.PSS(mgf=padding.MGF1(hashfunc), salt_length=saltlen), Prehashed(hashfunc)
            )
        elif sigalg == tpm2_objects.TPM_ALG_RSASSA:
            pubkey.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashfunc))
        else:
            raise Exception("Unsupported singature scheme")
    elif isinstance(pubkey, EllipticCurvePublicKey):
        pubkey.verify(sig, digest, ec.ECDSA(Prehashed(hashfunc)))
    else:
        raise Exception("Unsupported singature scheme")


def der_int(int_bytes: bytes) -> bytes:
    from_bytes = int.from_bytes(int_bytes, "big")
    hex_enc = f"{from_bytes:x}".encode()
    if len(hex_enc) % 2:
        hex_enc = b"0" + hex_enc
    encoded_int = binascii.unhexlify(hex_enc)
    first = encoded_int[0]
    if first <= 0x7F:
        return b"\x02" + der_len(len(encoded_int)) + encoded_int
    return b"\x02" + der_len(len(encoded_int) + 1) + b"\x00" + encoded_int


def der_len(encoded_int_len: int) -> bytes:
    if encoded_int_len < 0x80:
        return bytes((encoded_int_len,))
    hex_enc = f"{encoded_int_len:x}".encode()
    if len(hex_enc) % 2:
        hex_enc = b"0" + hex_enc
    bin_str = binascii.unhexlify(hex_enc)
    return bytes((0x80 | len(bin_str),)) + bin_str


def ecdsa_der_from_tpm(sigblob: bytes) -> bytes:
    _, _, sig_size_r = struct.unpack_from(">HHH", sigblob, 0)
    sig_r = sigblob[6 : 6 + sig_size_r]
    encoded_sig_r = der_int(sig_r)
    sigblob = sigblob[6 + sig_size_r :]
    sig_size_s = struct.unpack_from(">H", sigblob, 0)[0]
    sig_s = sigblob[2 : 2 + sig_size_s]
    encoded_sig_s = der_int(sig_s)
    total_size = len(encoded_sig_r) + len(encoded_sig_s)
    der_sig = bytes.fromhex(f"30{total_size:x}") + encoded_sig_r + encoded_sig_s
    return der_sig


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

    verify(pubkey, signature, quote_digest, hashfunc)

    # Check that reported nonce is expected one
    retDict = tpm2_objects.unmarshal_tpms_attest(quoteblob)
    extradata = retDict["extraData"]
    if extradata.decode("utf-8") != nonce:
        raise Exception("The nonce from the attestation differs from the expected nonce")

    # Check that correct quote_digest was used which is equivalent to hash(quoteblob)
    compare_digest, pcrs_dict = __get_and_hash_pcrs(pcrblob, hash_alg)
    if retDict["attested.quote.pcrDigest"] != compare_digest:
        raise Exception("The digest used for quoting is different than the one that was calculated")

    return pcrs_dict


def label_to_bytes(label: str) -> bytes:
    return bytes(label, "UTF-8") + b"\x00"


def makecredential(ek_tpm: bytes, challenge: bytes, aik_name: bytes) -> bytes:
    """TPM_MakeCredential implementation

    Parameters
    ----------
    ek_tpm: marshalled TPMT_PUBKEY
    challenge: random 'password'
    aik_name: name of the object (AIK)
    """
    public_key, hash_alg = tpm2_objects.pubkey_parms_from_tpm2b_public(ek_tpm)

    hashfunc = tpm2_objects.HASH_FUNCS.get(hash_alg)
    if not hashfunc:
        raise ValueError(f"Unsupported hash with id {hash_alg:#x} in signature blob")

    if isinstance(public_key, RSAPublicKey):
        random = os.urandom(hashfunc.digest_size)

        secret = public_key.encrypt(
            random,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashfunc), algorithm=hashfunc, label=label_to_bytes("IDENTITY")),
        )
    elif isinstance(public_key, EllipticCurvePublicKey):
        random, secret = crypt_secret_encrypt_ecc(public_key, hashfunc)
    else:
        raise ValueError(f"Unsupported public key type {type(public_key)} for makecredential")

    credentialblob = secret_to_credential(challenge, aik_name, random, ek_tpm, hashfunc)

    # Create tpm2-tools-specific result format
    hdr = struct.pack(">II", 0xBADCC0DE, 1)
    tail = struct.pack(f">H{len(secret)}s", len(secret), secret)

    return hdr + credentialblob + tail


def crypt_secret_encrypt_ecc(public_key: EllipticCurvePublicKey, hashfunc: hashes.HashAlgorithm) -> Tuple[bytes, bytes]:
    my_private_key = ec.generate_private_key(public_key.curve)

    my_public_key = my_private_key.public_key()
    point = tpm2_objects.tpms_ecc_point_marshal(my_public_key)

    ecc_secret_x = my_private_key.exchange(ec.ECDH(), public_key)

    digest_size = hashfunc.digest_size

    x = my_public_key.public_numbers().x
    party_x = x.to_bytes((x.bit_length() + 7) >> 3, "big")

    x = public_key.public_numbers().x
    party_y = x.to_bytes((x.bit_length() + 7) >> 3, "big")

    data = crypt_kdfe(hashfunc, ecc_secret_x, "IDENTITY", party_x, party_y, digest_size << 3)

    return data, point


def secret_to_credential(
    secret: bytes, name: bytes, seed: bytes, ek_tpm: bytes, hashfunc: hashes.HashAlgorithm
) -> bytes:
    """TPM 2's SecretToCredential

    Parameters
    ----------
    secret: the secret
    name: name of the object
    seed: external seed
    ek_tpm: marshalled TPMT_PUBKEY
    hashfunc: the hash function used by the public key (extracted from ek_tpm)
    """
    # sensitive data is the 2nd part in TPM2B_ID_OBJECT
    sensitive_data_2b = struct.pack(f">H{len(secret)}s", len(secret), secret)
    integrity, sensitive_data_enc = produce_outer_wrap(ek_tpm, name, hashfunc, seed, sensitive_data_2b)

    tpms_id_object = struct.pack(
        f">H{len(integrity)}s{len(sensitive_data_enc)}s",
        len(integrity),
        integrity,
        sensitive_data_enc,
    )

    return struct.pack(f">H{len(tpms_id_object)}s", len(tpms_id_object), tpms_id_object)


def produce_outer_wrap(
    ek_tpm: bytes,
    name: bytes,
    hashfunc: hashes.HashAlgorithm,
    seed: bytes,
    sensitive_data_2b: bytes,
) -> Tuple[bytes, bytes]:
    """TPM 2's ProduceOuterWrap implementing encrypt-then-MAC of a secret

    Parameters
    ----------
    ek_tpm: marshalled TPMT_PUBKEY
    name: name of the object
    hashfunc: the hash function used by the public key (extracted from ek_tpm)
    seed: external seed
    sensitive_data_2b: marshalled TPM2B buffer holding a secret
    """
    symkey, sym_alg = compute_protection_key_parms(ek_tpm, hashfunc, name, seed)

    # Encrypt inner buffer
    symcipherfunc = tpm2_objects.SYMCIPHER_FUNCS.get(sym_alg)
    if not symcipherfunc:
        raise ValueError(f"Unsupported symmetric cipher with Id {sym_alg:#x} was requested")

    symcipher = symcipherfunc(symkey)
    block_size = symcipher.block_size >> 3
    encryptor = Cipher(symcipher, modes.CFB(b"\x00" * block_size)).encryptor()
    ciphertext = encryptor.update(sensitive_data_2b) + encryptor.finalize()

    # Compute outer integrity
    hmac_signature = compute_outer_integrity(name, hashfunc, seed, ciphertext)

    return hmac_signature, ciphertext


def compute_outer_integrity(
    name: bytes,
    hashfunc: hashes.HashAlgorithm,
    seed: bytes,
    ciphertext: bytes,
) -> bytes:
    """TPM 2's ComputeOuterIntegrity HMAC'ing a ciphertext

    Parameters
    ----------
    name: name of the object; this will be part of the HMAC'ed data
    hashfunc: hash function to use for HMAC
    seed: external seed
    ciphertext: ciphertext to HMAC
    """
    digest_size = hashfunc.digest_size

    hmac_key = crypt_kdfa(hashfunc, seed, "INTEGRITY", b"", b"", digest_size << 3)

    h = hmac.HMAC(hmac_key, hashfunc)
    h.update(ciphertext)
    h.update(name)
    return h.finalize()


def compute_protection_key_parms(
    ek_tpm: bytes, hashfunc: hashes.HashAlgorithm, name: bytes, seed: bytes
) -> Tuple[bytes, int]:
    """TPM 2's ComputeProtectionKeyParms deriving a symmetric key using KDFa

    Parameters
    ----------
    ek_tpm: marshalled TPMT_PUBKEY
    hashfunc: hash function to use for key derivation
    name: name of the object
    seed: external seed
    """
    assert len(seed) > 0

    sym_alg, symkey_bits = tpm2_objects.get_tpm2b_public_symkey_params(ek_tpm)

    symkey = crypt_kdfa(hashfunc, seed, "STORAGE", name, b"", symkey_bits)

    return symkey, sym_alg


def crypt_kdfa(
    hashfunc: hashes.HashAlgorithm,
    key: bytes,
    label: str,
    context_u: bytes,
    context_v: bytes,
    size_in_bits: int,
) -> bytes:
    """TPM 2's KDFa

    Parameters
    ----------
    hashfunc: hash function
    key: key to use for HMAC
    label: a label to add to the HMAC
    context_u: context to add to the HMAC
    context_v: context to add to the HMAC
    size_in_bits: how many bits of random data to generate
    """
    size_in_bytes = (size_in_bits + 7) >> 3
    context = context_u + context_v

    kdf = KBKDFHMAC(
        algorithm=hashfunc,
        mode=Mode.CounterMode,
        length=size_in_bytes,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=bytes(label, "UTF-8"),
        context=context,
        fixed=None,
    )
    return kdf.derive(key)


def crypt_kdfe(
    hashfunc: hashes.HashAlgorithm,
    secret_x: bytes,
    label: str,
    party_x: bytes,
    party_y: bytes,
    size_in_bits: int,
) -> bytes:
    """TPM 2's KDFe

    Parameters
    ----------
    hashfunc: hash function
    secret_x: the X coordinate of the product of a public ECC key and a different private ECC key
    label: a label to add to the digest
    party_x: context to add to the digest
    party_y: context to add to the digest
    size_in_bits: how many bits of random data to generate
    """
    size_in_bytes = (size_in_bits + 7) >> 3
    label_bytes = label_to_bytes(label)
    otherinfo = label_bytes + party_x + party_y

    kdf = ConcatKDFHash(
        algorithm=hashfunc,
        length=size_in_bytes,
        otherinfo=otherinfo,
    )
    return kdf.derive(secret_x)


def crypt_hash(data: bytes, hash_alg: bytes) -> Tuple[bytes, hashes.HashAlgorithm]:
    """TPM_Hash implementation

    Parameters
    ----------
    data: data to be hashed
    hash_alg: hashing algorithm to be used
    """
    hashfunc = tpm2_objects.HASH_FUNCS.get(int.from_bytes(hash_alg, "big"))
    if not hashfunc:
        raise ValueError("Unsupported hash in signature blob")
    digest = hashes.Hash(hashfunc)
    digest.update(data)

    return digest.finalize(), hashfunc


def check_mask(mask: Optional[str], pcr: int) -> bool:
    if mask is None:
        return False
    return bool(1 << pcr & int(mask, 0))


def random_password(length: int = 20) -> str:
    rand = crypto.generate_random_key(length)
    chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
    password = ""
    for i in range(length):
        password += chars[(rand[i]) % len(chars)]
    return password


def readPolicy(configval: str) -> Dict[str, Any]:
    policy: Dict[str, Any] = json.loads(configval)

    # compute PCR mask from tpm_policy
    mask = 0
    for key in policy:
        if not key.isdigit() or int(key) > 24:
            raise Exception(f"Invalid tpm policy pcr number: {key}")

        if int(key) == config.TPM_DATA_PCR:
            raise Exception(f"Invalid allowlist PCR number {key}, keylime uses this PCR to bind data.")
        if int(key) == config.IMA_PCR:
            raise Exception(f"Invalid allowlist PCR number {key}, this PCR is used for IMA.")

        mask = mask | (1 << int(key))

        # wrap it in a list if it is a singleton
        if isinstance(policy[key], str):
            policy[key] = [policy[key]]

        # convert all hash values to lowercase
        policy[key] = [x.lower() for x in policy[key]]

    policy["mask"] = hex(mask)
    return policy
