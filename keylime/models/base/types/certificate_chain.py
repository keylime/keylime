import base64
from typing import Optional, TypeAlias, Union, List

import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy.types import Text

from keylime.models.base.type import ModelType
from keylime.cert_utils import to_cert_list


class CertificateChain(ModelType):
    """The CertificateChain class implements the model type API (by inheriting from ``ModelType``) to allow model fields to
    be declared as containing objects of type ``List[cryptography.x509.Certificate]``. When such a field is set, the incoming
    value is decoded as appropriate and cast to an ```List[cryptography.x509.Certificate]`` object. If saved to a database,
    the object is converted to its PEM representation and encoded as a string.
    """

    IncomingValue: TypeAlias = Union[str, None]

    def __init__(self) -> None:
        super().__init__(Text)

    def cast(self, value: IncomingValue) -> Optional[List[cryptography.x509.Certificate]]:
        """Tries to interpret the given value as a chain of X.509 certificates and convert it to a
        ``List[cryptography.x509.Certificate]`` object.

        :param value: The value to convert (PEM format)

        :raises :class:`ValueError`: if the given value cannot be interpreted as a chain of X.509 certificates.

        :returns: A ``List[cryptography.x509.Certificate]`` object or None if an empty value is given
        """
        if not value:
            return None

        return to_cert_list(value)

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be a valid X.509 certificate in PEM format or otherwise encoded using Base64"

    def _dump(self, value: IncomingValue) -> Optional[str]:
        # Cast incoming value to PEM certificate chain
        chain = ""
        for cert in value:
            chain += cert.public_bytes(Encoding.PEM).decode("utf-8")

        return chain

    def render(self, value: IncomingValue) -> Optional[str]:
        return self._dump(value) # type: ignore[no-any-return]

    @property
    def native_type(self) -> type:
        return List
