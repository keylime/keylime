import typing

try:
    # The following only exists with python-cryptography v37.0.x
    from cryptography.hazmat.primitives.asymmetric.types import CERTIFICATE_PRIVATE_KEY_TYPES as cpke
except ImportError:
    cpke = typing.Any  # type: ignore

CERTIFICATE_PRIVATE_KEY_TYPES = cpke
