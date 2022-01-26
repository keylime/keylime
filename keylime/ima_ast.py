'''
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Thore Sommer

AST with parser and validator for IMA ASCII entries.
Implements the templates (modes) and types as defined in:
- https://elixir.bootlin.com/linux/latest/source/security/integrity/ima/ima_template.c
- https://www.kernel.org/doc/html/v5.12/security/IMA-templates.html
'''

import binascii
import codecs
import struct
import abc

from typing import Dict, Callable, Any, Optional
from keylime import config
from keylime import keylime_logging
from keylime.common.algorithms import Hash
from keylime.failure import Failure, Component

logger = keylime_logging.init_logging("ima")

TCG_EVENT_NAME_LEN_MAX = 255
SHA_DIGEST_LEN = 20
MD5_DIGEST_LEN = 16

NULL_BYTE = ord('\0')
COLON_BYTE = ord(':')


def get_START_HASH(hash_alg: Hash):
    return codecs.decode(b'0' * (hash_alg.get_size() // 4), 'hex')


def get_FF_HASH(hash_alg: Hash):
    return codecs.decode(b'f' * (hash_alg.get_size() // 4), 'hex')


class Validator:
    functions: Dict[Any, Callable]

    def __init__(self, functions):
        self.functions = functions

    def get_validator(self, class_type) -> Callable:
        validator = self.functions.get(class_type, None)
        if validator is None:
            logger.warning(f"No validator was implemented for: {class_type} . Using always false validator!")
            failure = Failure(Component.IMA, ["validation"])
            failure.add_event("no_validator", f"No validator was implemented for: {class_type} . Using always false validator!", True)
            return lambda *_: failure
        return validator


class ParserError(TypeError):
    """Is thrown when a type could not be constructed successfully."""


class Mode(abc.ABC):
    @abc.abstractmethod
    def is_data_valid(self, validator: Validator):
        pass

    @abc.abstractmethod
    def bytes(self) -> bytes:
        pass


class Type(abc.ABC):
    @abc.abstractmethod
    def struct(self):
        pass


class HexData(Type):
    data: bytes

    def __init__(self, data: str):
        try:
            self.data = codecs.decode(data.encode("utf-8"), "hex")
        except binascii.Error as e:
            raise ParserError(f"Provided data was not valid hex: {data}") from e

    def __str__(self):
        return self.data.decode("utf-8")

    def struct(self):
        return struct.pack(f"<I{len(self.data)}s",
                           len(self.data),
                           self.data)


class Signature(HexData):
    """
    Class for type "sig".
    """
    def __init__(self, data: str):
        super().__init__(data)
        # basic checks on signature
        fmt = '>BBBIH'
        hdrlen = struct.calcsize(fmt)
        if len(self.data) < hdrlen:
            raise ParserError("Invalid signature: header too short")
        _, _, _, _, sig_size = struct.unpack(fmt, self.data[:hdrlen])

        if hdrlen + sig_size != len(self.data):
            raise ParserError("Invalid signature: malformed header")


class Buffer(HexData):
    """
    Class for type "buf".
    """


class Name(Type):
    """
    Class for type "n" and "n-ng".
    """
    name: str
    legacy: bool = False

    def __init__(self, name: str, legacy=False):
        self.name = name
        self.legacy = legacy

    def __str__(self):
        return self.name

    def struct(self):
        # The old "n" option is fixed length.
        if self.legacy:
            return struct.pack(f"{len(self.name)}sB{TCG_EVENT_NAME_LEN_MAX - len(self.name)}s",
                               self.name.encode("utf-8"),
                               NULL_BYTE,
                               bytearray(TCG_EVENT_NAME_LEN_MAX - len(self.name)))

        return struct.pack(f"<I{len(self.name)}sB",
                           len(self.name) + 1,
                           self.name.encode("utf-8"),
                           NULL_BYTE)


class Digest:
    """
    Class for types "d" and "d-ng" with and without algorithm
    """
    hash: bytes
    algorithm: Optional[str] = None
    legacy: bool = False

    def __init__(self, digest: str, legacy=False):
        self.legacy = legacy
        tokens = digest.split(":")
        if len(tokens) == 1:
            try:
                self.hash = codecs.decode(tokens[0].encode("utf-8"), "hex")
            except binascii.Error as e:
                raise ParserError(f"Digest hash is not valid hex. Got: {tokens[0]}") from e
            if not (len(self.hash) == SHA_DIGEST_LEN or len(self.hash) == MD5_DIGEST_LEN):
                raise ParserError(
                    "Cannot create Digest. No hash algorithm is provided and hash does not belong to a md5 or sha1 hash.")
        elif len(tokens) == 2:
            try:
                self.hash = codecs.decode(tokens[1].encode("utf-8"), "hex")
            except binascii.Error as e:
                raise ParserError(f"Digest hash is not valid hex. Got: {tokens[1]}") from e
            self.algorithm = tokens[0]
        else:
            raise ParserError(f"Cannot create Digest expected 1 or 2 tokens got: {len(tokens)} for {digest}")

    def struct(self):
        # The legacy format "d" has fixed length, so it does not contain a length attribute
        if self.legacy:
            return struct.pack(f"<{len(self.hash)}s", self.hash)

        if self.algorithm is None:
            return struct.pack(f"<I{len(self.hash)}s", len(self.hash), self.hash)
        # After the ':' must be a '\O':
        # https://elixir.bootlin.com/linux/v5.12.10/source/security/integrity/ima/ima_template_lib.c#L230
        return struct.pack(f"<I{len(self.algorithm)}sBB{len(self.hash)}s",
                           len(self.algorithm) + 2 + len(self.hash),
                           self.algorithm.encode("utf-8"),
                           COLON_BYTE,
                           NULL_BYTE,
                           self.hash)


class Ima(Mode):
    """
    Class for "ima". Contains the digest and a path.
    """
    digest: Digest
    path: Name

    def __init__(self, data: str):
        tokens = data.split()
        if len(tokens) != 2:
            raise ParserError()
        self.digest = Digest(tokens[0], legacy=True)
        self.path = Name(tokens[1], legacy=True)

    def bytes(self):
        return self.digest.struct() + self.path.struct()


    def is_data_valid(self, validator: Validator):
        return validator.get_validator(type(self))(self.digest, self.path)


class ImaNg(Mode):
    """
    Class for "ima-ng". Contains the digest and a path.
    """
    digest: Digest
    path: Name

    def __init__(self, data: str):
        tokens = data.split()
        if len(tokens) != 2:
            raise ParserError(f"Cannot create ImaSig expected 2 tokens got: {len(tokens)}.")
        self.digest = Digest(tokens[0])
        self.path = Name(tokens[1])

    def bytes(self):
        return self.digest.struct() + self.path.struct()

    def is_data_valid(self, validator):
        return validator.get_validator(type(self))(self.digest, self.path)


class ImaSig(Mode):
    """
    Class for "ima-sig" template. Nearly the same as ImaNg but can contain a optional signature.
    """
    digest: Digest
    path: Name
    signature: Optional[Signature] = None

    def __init__(self, data: str):
        tokens = data.split(maxsplit=4)
        num_tokens = len(tokens)
        if num_tokens == 2:
            self.digest = Digest(tokens[0])
            self.path = Name(tokens[1])
        elif num_tokens <= 1:
            raise ParserError(f"Cannot create ImaSig expected 2 or 3 tokens got: {len(tokens)}.")
        else:
            self.digest = Digest(tokens[0])
            signature = self.create_Signature(tokens[-1])
            if signature:
                self.signature = signature
                if num_tokens == 3:
                    self.path = Name(tokens[1])
                else:
                    # first part of data is digest , last is signature, in between is path
                    self.path = data.split(maxsplit=1)[1].rsplit(maxsplit=1)[0]
            else:
                # first part is data, last part is path
                self.path = data.split(maxsplit=1)[1]

    def create_Signature(self, hexstring):
        """ Create the Signature object if the hexstring is a valid signature """
        try:
            return Signature(hexstring)
        except ParserError:
            pass
        return None

    def bytes(self):
        output = self.digest.struct() + self.path.struct()
        # If no signature is there we sill have to add the entry for it
        if self.signature is None:
            output += struct.pack("<I0s", 0, b'')
        else:
            output += self.signature.struct()
        return output

    def is_data_valid(self, validator):
        return validator.get_validator(type(self))(self.digest, self.path, self.signature)


class ImaBuf(Mode):
    """
    Class for "ima-buf". Contains a digest, buffer name and the buffer itself.
    For validation the buffer must be done based on the name because IMA only provides it as an byte array.
    """
    digest: Digest
    name: Name
    data: Buffer

    def __init__(self, data: str):
        tokens = data.split(maxsplit=5)
        if len(tokens) != 3:
            raise ParserError(f"Cannot create ImaBuf expected 3 tokens got: {len(tokens)}.")
        self.digest = Digest(tokens[0])
        self.name = Name(tokens[1])
        self.data = Buffer(tokens[2])

    def bytes(self):
        return self.digest.struct() + self.name.struct() + self.data.struct()

    def is_data_valid(self, validator: Validator):
        return validator.get_validator(type(self))(self.digest, self.name, self.data)


class Entry:
    """
    IMA Entry. Contains the PCR, template hash and mode.
    """
    pcr: str
    ima_template_hash: bytes
    pcr_template_hash: bytes
    mode: Mode
    _bytes: bytes
    _validator: Validator
    _ima_hash_alg: Hash
    _pcr_hash_alg: Hash

    _mode_lookup = {
        "ima": Ima,
        "ima-ng": ImaNg,
        "ima-sig": ImaSig,
        "ima-buf": ImaBuf
    }

    def __init__(self, data: str, validator=None, ima_hash_alg: Hash = Hash.SHA1, pcr_hash_alg: Hash = Hash.SHA1):
        self._validator = validator
        self._ima_hash_alg = ima_hash_alg
        self._pcr_hash_alg = pcr_hash_alg
        tokens = data.split(maxsplit=3)
        if len(tokens) != 4:
            raise ParserError(f"Cannot create Entry expected 4 tokens got: {len(tokens)}.")
        self.pcr = tokens[0]
        try:
            self.ima_template_hash = codecs.decode(tokens[1].encode(), "hex")
        except binascii.Error as e:
            raise ParserError(f"Cannot create Entry expected 4 tokens got: {len(tokens)}.") from e

        mode = self._mode_lookup.get(tokens[2], None)
        if mode is None:
            raise ParserError(f"No parser for mode {tokens[2]} implemented.")
        self.mode = mode(tokens[3])
        self._bytes = self.mode.bytes()
        self.pcr_template_hash = self._pcr_hash_alg.hash(self._bytes)
        # Set correct hash for time of measure, time of use (ToMToU) errors
        # and if a file is already opened for write.
        # https://elixir.bootlin.com/linux/v5.12.12/source/security/integrity/ima/ima_main.c#L101
        if self.ima_template_hash == get_START_HASH(ima_hash_alg):
            self.ima_template_hash = get_FF_HASH(ima_hash_alg)
            self.pcr_template_hash = get_FF_HASH(pcr_hash_alg)

    def invalid(self):
        failure = Failure(Component.IMA, ["validation"])
        if self.pcr != str(config.IMA_PCR):
            logger.warning(f"IMA entry PCR does not match {config.IMA_PCR}. It was: {self.pcr}")
            failure.add_event("ima_pcr", {"message": "IMA PCR is not the configured one",
                                          "expected": str(config.IMA_PCR), "got": self.pcr}, True)

        # Ignore template hash for ToMToU errors
        if self.ima_template_hash == get_FF_HASH(self._ima_hash_alg):
            logger.warning("Skipped template_hash validation entry with FF_HASH")
            # By default ToMToU errors are not treated as a failure
            if config.getboolean("cloud_verifier", "tomtou_errors", fallback=False):
                failure.add_event("tomtou", "hash validation was skipped", True)
            return failure
        if self.ima_template_hash != self._ima_hash_alg.hash(self._bytes):
            failure.add_event("ima_hash",
                              {"message": "IMA template hash does not match the calculated hash.",
                               "expected": str(self.ima_template_hash), "got": str(self.mode.bytes())}, True)
            return failure
        if self._validator is None:
            failure.add_event("no_validator", "No validator specified", True)
            return failure

        failure.merge(self.mode.is_data_valid(self._validator))
        return failure
