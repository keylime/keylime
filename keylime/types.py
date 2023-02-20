import os
import sys
import typing

try:
    # The following only exists with python-cryptography v37.0.x
    from cryptography.hazmat.primitives.asymmetric.types import CERTIFICATE_PRIVATE_KEY_TYPES as cpke
except ImportError:
    cpke = typing.Any  # type: ignore

CERTIFICATE_PRIVATE_KEY_TYPES = cpke

if sys.version_info < (3, 7):
    # 3.6 does not allow subscription; 3.9 allows it
    PathLike_str = os.PathLike
else:
    PathLike_str = os.PathLike[str]  # pylint: disable=unsubscriptable-object
