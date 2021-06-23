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
import hashlib
import struct
import abc
import dataclasses

from typing import Dict, Callable, Any, Optional
from keylime import keylime_logging

logger = keylime_logging.init_logging("ima")

TCG_EVENT_NAME_LEN_MAX = 255
SHA_DIGEST_LEN = 20
MD5_DIGEST_LEN = 16

START_HASH = (codecs.decode(b'0000000000000000000000000000000000000000', 'hex'))
FF_HASH = (codecs.decode(b'ffffffffffffffffffffffffffffffffffffffff', 'hex'))

NULL_BYTE = ord('\0')
COLON_BYTE = ord(':')


@dataclasses.dataclass
class Validator:
    functions: Dict[Any, Callable]

    def get_validator(self, class_type) -> Callable:
        validator = self.functions.get(class_type, None)
        if validator is None:
            logger.warning(f"No validator was implemented for: {class_type} . Using always false validator!")
            return lambda *_: False
        return validator


class ParserError(TypeError):
    """Is thrown when a type could not be constructed successfully."""


class Mode(abc.ABC):
    @abc.abstractmethod
    def is_data_valid(self, validator: Validator):
        pass

    @abc.abstractmethod
    def hash(self) -> bytes:
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

    def hash(self):
        tohash = self.digest.struct() + self.path.struct()
        return hashlib.sha1(tohash).digest()

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

    def hash(self):
        tohash = self.digest.struct() + self.path.struct()
        return hashlib.sha1(tohash).digest()

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
        if len(tokens) in [2, 3]:
            self.digest = Digest(tokens[0])
            self.path = Name(tokens[1])
        else:
            raise ParserError(f"Cannot create ImaSig expected 2 or 3 tokens got: {len(tokens)}.")

        if len(tokens) == 3:
            self.signature = Signature(tokens[2])

    def hash(self):
        tohash = self.digest.struct() + self.path.struct()
        # If no signature is there we sill have to add the entry for it
        if self.signature is None:
            tohash += struct.pack("<I0s", 0, b'')
        else:
            tohash += self.signature.struct()
        return hashlib.sha1(tohash).digest()

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

    def hash(self):
        tohash = self.digest.struct() + self.name.struct() + self.data.struct()
        return hashlib.sha1(tohash).digest()

    def is_data_valid(self, validator: Validator):
        return validator.get_validator(type(self))(self.digest, self.name, self.data)


class Entry:
    """
    IMA Entry. Contains the PCR, template hash and mode.
    """
    pcr: str
    template_hash: bytes
    mode: Mode
    validator: Validator

    mode_lookup = {
        "ima": Ima,
        "ima-ng": ImaNg,
        "ima-sig": ImaSig,
        "ima-buf": ImaBuf
    }

    def __init__(self, data: str, validator=None):
        self.validator = validator
        tokens = data.split(maxsplit=3)
        if len(tokens) != 4:
            raise ParserError(f"Cannot create Entry expected 4 tokens got: {len(tokens)}.")
        self.pcr = tokens[0]
        try:
            self.template_hash = codecs.decode(tokens[1].encode(), "hex")
        except binascii.Error as e:
            raise ParserError(f"Cannot create Entry expected 4 tokens got: {len(tokens)}.") from e

        mode = self.mode_lookup.get(tokens[2], None)
        if mode is None:
            raise ParserError(f"No parser for mode {tokens[2]} implemented.")
        self.mode = mode(tokens[3])

        # Ignore time of measure, time of use (ToMToU) errors and if a file is already opened for write.
        # TODO make this configurable
        # https://elixir.bootlin.com/linux/v5.12.12/source/security/integrity/ima/ima_main.c#L101
        if self.template_hash == START_HASH:
            self.template_hash = FF_HASH

    def valid(self):
        # Ignore template hash for ToMToU errors
        if self.template_hash == FF_HASH:
            logger.warning("Skipped template_hash validation entry with FF_HASH")
            return self.mode.is_data_valid(self.validator)
        if self.template_hash != self.mode.hash():
            return False
        if self.validator is None:
            return False

        return self.mode.is_data_valid(self.validator)
