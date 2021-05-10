#!/usr/bin/env python3
'''
SPDX-License-Identifier: Apache-2.0
'''

import base64
import enum
import json
import struct

from cryptography import x509
from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

from keylime import keylime_logging


logger = keylime_logging.init_logging('ima_file_signatures')


"""
Tools for IMA file signature verification
"""


class HashAlgo(enum.IntEnum):
    """ The hash_algo's as Linux defines them:
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
@utils.register_interface(hashes.HashAlgorithm)
class MyStreebog256():
    """ Basic class for Streebog256 """
    name = "streebog256"
    digest_size = 32
    block_size = 64


@utils.register_interface(hashes.HashAlgorithm)
class MyStreebog512():
    """ Basic class for Streebog512 """
    name = "streebog512"
    digest_size = 64
    block_size = 64


HASH_FUNCS = {
    # The list of hash functions we need for signature verification.
    HashAlgo.HASH_ALGO_MD5: hashes.__dict__.get('MD5'),
    HashAlgo.HASH_ALGO_SHA1: hashes.__dict__.get('SHA1'),
    HashAlgo.HASH_ALGO_SHA256: hashes.__dict__.get('SHA256'),
    HashAlgo.HASH_ALGO_SHA384: hashes.__dict__.get('SHA384'),
    HashAlgo.HASH_ALGO_SHA512: hashes.__dict__.get('SHA512'),
    HashAlgo.HASH_ALGO_SHA224: hashes.__dict__.get('SHA224'),
    HashAlgo.HASH_ALGO_STREEBOG_256: MyStreebog256,
    HashAlgo.HASH_ALGO_STREEBOG_512: MyStreebog512,
}


class EvmImaXattrType(enum.IntEnum):
    """ https://elixir.bootlin.com/linux/v5.9.8/source/security/integrity/integrity.h#L74
    """
    IMA_XATTR_DIGEST = 1
    EVM_XATTR_HMAC = 2
    EVM_IMA_XATTR_DIGSIG = 3
    IMA_XATTR_DIGEST_NG = 4
    EVM_XATTR_PORTABLE_DIGSIG = 5


class PubkeyAlgo(enum.IntEnum):
    """ https://elixir.bootlin.com/linux/v5.9.8/source/include/linux/digsig.h#L17 """
    PUBKEY_ALGO_RSA = 0


class ImaKeyring:
    """ ImaKeyring models an IMA keyring where keys are indexed by their keyid """

    def __init__(self):
        """ Constructor """
        self.ringv2 = {}

    @staticmethod
    def _get_keyidv2(pubkey):
        """ Calculate the keyidv2 of a given public key object. The keyidv2
            are the lowest 4 bytes of the sha1 hash over the public key bytes
            of a DER-encoded key in PKCS1 format.
        """
        if isinstance(pubkey, RSAPublicKey):
            fmt = serialization.PublicFormat.PKCS1
            pubbytes = pubkey.public_bytes(encoding=serialization.Encoding.DER,
                                           format=fmt)
        elif isinstance(pubkey, EllipticCurvePublicKey):
            fmt = serialization.PublicFormat.UncompressedPoint
            pubbytes = pubkey.public_bytes(encoding=serialization.Encoding.X962,
                                           format=fmt)
        else:
            raise UnsupportedAlgorithm("Unsupported public key type %s" %
                                       type(pubkey))

        default_be = backends.default_backend()
        digest = hashes.Hash(hashes.SHA1(), backend=default_be)
        digest.update(pubbytes)
        keydigest = digest.finalize()
        return int.from_bytes(keydigest[16:], 'big')

    def add_pubkey(self, pubkey):
        """ Add a public key object to the keyring. """
        keyidv2 = ImaKeyring._get_keyidv2(pubkey)
        # it's unlikely that two different public keys have the same 32 bit keyidv2
        self.ringv2[keyidv2] = pubkey
        logger.debug("Added key with keyid: 0x%08x" % keyidv2)

    def get_pubkey_by_keyidv2(self, keyidv2):
        """ Get a public key object given its keyidv2 """
        return self.ringv2.get(keyidv2)

    def to_json(self):
        """ Convert the ImaKeyring into a JSON object """
        fmt = serialization.PublicFormat.SubjectPublicKeyInfo
        obj = {}
        lst = []

        for pubkey in self.ringv2.values():
            try:
                pubbytes = pubkey.public_bytes(encoding=serialization.Encoding.DER,
                                               format=fmt)
            except Exception as ex:
                logger.error("Could not serialize key: %s" % str(ex))
            lst.append(pubbytes)

        obj['pubkeys'] = [base64.b64encode(pubkey).decode('ascii') for pubkey in lst]
        return obj

    def to_string(self):
        """ Generate a string representation """
        return json.dumps(self.to_json())

    @staticmethod
    def _base64_to_der_keylist(base64_keylist):
        """ Convert a base64-encoded list of public keys to a list of DER-encoded
            public keys
        """
        res = []
        for entry in base64_keylist:
            res.append(base64.b64decode(entry))
        return res

    @staticmethod
    def from_string(stringrepr):
        """ Convert a string-encoded ImaKeyring to an ImaKeyring object """
        if not stringrepr:
            return None

        ima_keyring = ImaKeyring()

        default_be = backends.default_backend()

        # An empty Db entry comes as a string '[]'. A valid DB entry as a string
        # ith escaped quotes and needs to be loaded twice
        obj = json.loads(stringrepr)
        if isinstance(obj, str):
            obj = json.loads(obj)
        if not isinstance(obj, dict):
            return None

        for der_key in ImaKeyring._base64_to_der_keylist(obj['pubkeys']):
            try:
                pubkey = serialization.load_der_public_key(der_key, backend=default_be)
                ima_keyring.add_pubkey(pubkey)
            except Exception as ex:
                logger.error("Could not load a base64-decoded DER key: %s" % str(ex))
        return ima_keyring

    @staticmethod
    def _verify(pubkey, sig, filehash, hashfunc):
        """ Do signature verification with the given public key """
        if isinstance(pubkey, RSAPublicKey):
            pubkey.verify(sig, filehash,
                          padding.PKCS1v15(), Prehashed(hashfunc))
        elif isinstance(pubkey, EllipticCurvePublicKey):
            pubkey.verify(sig, filehash,
                          ec.ECDSA(Prehashed(hashfunc)))

    def _asymmetric_verify(self, signature, filehash, filehash_type):
        """ Do an IMA signature verification given the signature data from
            the log, which is formatted as 'struct signature_v2_hdr'.
            This function resembles the kernel code:
            https://elixir.bootlin.com/linux/v5.9/source/security/integrity/digsig_asymmetric.c#L76
            https://elixir.bootlin.com/linux/v5.9/source/security/integrity/integrity.h#L116
        """

        siglen = len(signature)

        # The data are in big endian
        fmt = '>BBBIH'
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
            logger.warning("Unsupported hash algo with id '%d'" % hash_algo)
            return False

        if filehash_type != hashfunc().name:
            logger.warning("Mismatching filehash type %s and ima signature hash used %s" %
                           (filehash_type, hashfunc().name))
            return False

        pubkey = self.get_pubkey_by_keyidv2(keyidv2)
        if not pubkey:
            logger.warning("No key with id 0x%08x available" % keyidv2)
            return False

        try:
            ImaKeyring._verify(pubkey, signature[hdrlen:], filehash, hashfunc())
        except InvalidSignature:
            return False
        return True

    def integrity_digsig_verify(self, signature, filehash, filehash_type):
        """ Given a system-specific keyring validate the signature against the
            given hash. This function resembles the kernel code at:
            https://elixir.bootlin.com/linux/v5.9/source/security/integrity/digsig.c#L59
        """
        fmt = '>BB'
        if len(signature) < struct.calcsize(fmt):
            logger.warning("Malformed signature: not enough bytes")
            return False

        typ, version = struct.unpack(fmt, signature[:struct.calcsize(fmt)])
        if typ not in [EvmImaXattrType.EVM_IMA_XATTR_DIGSIG,
                       EvmImaXattrType.EVM_XATTR_PORTABLE_DIGSIG]:
            logger.warning("Malformed signature: wrong type")
            return False

        if version == 2:
            return self._asymmetric_verify(signature, filehash, filehash_type)

        logger.warning("Malformed signature: wrong version (%d)" % version)
        return False


def _get_pubkey_from_der_public_key(filedata, backend):
    """ Load the filedata as a DER public key """
    try:
        return serialization.load_der_public_key(filedata, backend=backend)
    except Exception:
        return None


def _get_pubkey_from_pem_public_key(filedata, backend):
    """ Load the filedata as a PEM public key """
    try:
        return serialization.load_pem_public_key(filedata, backend=backend)
    except Exception:
        return None


def _get_pubkey_from_der_private_key(filedata, backend):
    """ Load the filedata as a DER private key """
    try:
        privkey = serialization.load_der_private_key(filedata, None,
                                                     backend=backend)
        return privkey.public_key()
    except Exception:
        return None


def _get_pubkey_from_pem_private_key(filedata, backend):
    """ Load the filedata as a PEM private key """
    try:
        privkey = serialization.load_pem_private_key(filedata, None,
                                                     backend=backend)
        return privkey.public_key()
    except Exception:
        return None


def _get_pubkey_from_der_x509_certificate(filedata, backend):
    """ Load the filedata as a DER x509 certificate """
    try:
        cert = x509.load_der_x509_certificate(filedata, backend=backend)
        return cert.public_key()
    except Exception:
        return None


def _get_pubkey_from_pem_x509_certificate(filedata, backend):
    """ Load the filedata as a PEM x509 certificate """
    try:
        cert = x509.load_pem_x509_certificate(filedata, backend=backend)
        return cert.public_key()
    except Exception:
        return None


def get_pubkey(filedata):
    """ Get the public key from the filedata.
        To make it easy for the user, we try to parse the filedata as
        PEM- or DER-encoded public key, x509 certificate, or even private key.
        This function then returns the public key object or None if the file
        contents could not be interpreted as a key.
    """
    default_be = backends.default_backend()
    for func in [_get_pubkey_from_der_public_key,
                 _get_pubkey_from_pem_public_key,
                 _get_pubkey_from_der_x509_certificate,
                 _get_pubkey_from_pem_x509_certificate,
                 _get_pubkey_from_der_private_key,
                 _get_pubkey_from_pem_private_key]:
        pubkey = func(filedata, default_be)
        if pubkey:
            return pubkey

    return None


def get_pubkey_from_file(filename):
    """ Get the public key object from a file """
    try:
        with open(filename, "rb") as fobj:
            filedata = fobj.read()
            pubkey = get_pubkey(filedata)
            if pubkey:
                return pubkey
    except Exception:
        pass

    return None
