r"""DSSE signing implementation.

Based on the reference implementation at: https://github.com/secure-systems-lab/dsse/tree/master/implementation.
"""

import base64
import binascii
import json
from abc import ABCMeta, abstractmethod

# Protocol requires Python 3.8+.
from typing import Iterable, List, Optional, Tuple


class Signer(metaclass=ABCMeta):
    @abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Returns the signature of `message`."""

    def keyid(self) -> Optional[str]:
        """Returns the ID of this key, or None if not supported."""


class Verifier:
    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Returns true if `message` was signed by `signature`."""

    def keyid(self) -> Optional[str]:
        """Returns the ID of this key, or None if not supported."""


# Collection of verifiers, each of which is associated with a name.
VerifierList = Iterable[Tuple[str, Verifier]]


class VerifiedPayload:
    payloadType: str
    payload: bytes
    recognizedSigners: List[str]  # List of names of signers

    def __init__(self, payloadType: str, payload: bytes, recognizedSigners: List[str]):
        self.payloadType = payloadType
        self.payload = payload
        self.recognizedSigners = recognizedSigners


def b64enc(m: bytes) -> str:
    return base64.standard_b64encode(m).decode("utf-8")


def b64dec(m_str: str) -> bytes:
    m = m_str.encode("utf-8")

    decoded: Optional[bytes] = None
    try:
        decoded = binascii.unhexlify(m)
    except binascii.Error:
        pass
    if not decoded:
        try:
            decoded = base64.b64decode(m, validate=True)
        except binascii.Error:
            decoded = base64.b64decode(m, altchars="-_", validate=True)
    return decoded


def PAE(payloadType: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %b %d %b" % (len(payloadType), payloadType.encode("utf-8"), len(payload), payload)


def Sign(payloadType: str, payload: bytes, signer: Signer) -> str:
    signature = {
        "keyid": signer.keyid(),
        "sig": b64enc(signer.sign(PAE(payloadType, payload))),
    }
    if not signature["keyid"]:
        del signature["keyid"]
    return json.dumps(
        {
            "payload": b64enc(payload),
            "payloadType": payloadType,
            "signatures": [signature],
        }
    )


def Verify(json_signature: str, verifiers: VerifierList, strict_id_matching: Optional[bool] = False) -> VerifiedPayload:
    wrapper = json.loads(json_signature)
    payloadType = wrapper["payloadType"]
    payload = b64dec(wrapper["payload"])
    pae = PAE(payloadType, payload)
    recognizedSigners = []
    for signature in wrapper["signatures"]:
        for name, verifier in verifiers:
            if (
                strict_id_matching
                and signature.get("keyid") is not None
                and verifier.keyid() is not None
                and signature.get("keyid") != verifier.keyid()
            ):
                continue
            if verifier.verify(pae, b64dec(signature["sig"])):
                recognizedSigners.append(name)
    if not recognizedSigners:
        raise ValueError("No valid signature found")
    return VerifiedPayload(payloadType, payload, recognizedSigners)


if __name__ == "__main__":
    import doctest

    doctest.testmod()
