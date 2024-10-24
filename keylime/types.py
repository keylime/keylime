import os
import sys
import typing

# pylint: disable=unused-import

CERTIFICATE_PRIVATE_KEY_TYPES = typing.Any

try:
    # The following only exists with python-cryptography v40.0.x
    from cryptography.hazmat.primitives.asymmetric.types import (
        CertificateIssuerPrivateKeyTypes as CERTIFICATE_PRIVATE_KEY_TYPES,
    )
except ImportError:
    # fall back to older version
    try:
        # The following only exists with python-cryptography v37.0.x
        from cryptography.hazmat.primitives.asymmetric.types import CERTIFICATE_PRIVATE_KEY_TYPES
    except ImportError:
        pass

if sys.version_info < (3, 9):
    # 3.8 does not allow subscription; 3.9 requires it
    PathLike_str = os.PathLike
else:
    PathLike_str = os.PathLike[str]  # pylint: disable=unsubscriptable-object
