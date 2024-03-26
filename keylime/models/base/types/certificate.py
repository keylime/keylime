import base64
import binascii

import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.error import PyAsn1Error, SubstrateUnderrunError
from sqlalchemy.types import Text

from keylime import cert_utils
from keylime.models.base.type import ModelType


class Certificate(ModelType):
    """The Certificate class implements the model type API (by inheriting from ``ModelType``) to allow model fields to
    be declared as containing objects of type ``cryptography.x509.Certificate``. When such a field is set, the incoming
    value is decoded as appropriate and cast to an ``cryptography.x509.Certificate`` object. If saved to a database, the
    object is converted to its DER representation and encoded as a string using Base64.

    The schema of the backing database table is thus assumed to declare the certificate-containing column as type
    ``"Text"`` or comparable, in line with established Keylime convention.

    Example 1
    ---------

    To use the Certificate type, declare a model field as in the following example::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("cert", Certificate, nullable=True)
                # (Any additional schema declarations...)

    Then, you can set the field by providing:

    * a previously-instantiated ``cryptography.x509.Certificate`` object;
    * a ``bytes`` object containing DER-encoded binary certificate data; or
    * a ``str`` object containing DER binary certificate data which has been Base64 encoded; or
    * a ``str`` object containing PEM-encoded certificate data.

    This is shown in the code sample below::

        record = SomeModel.empty()

        # Set cert field using ``certificate`` which is of type ``cryptography.x509.Certificate``:
        record.cert = certificate

        # Set cert field using DER binary data:
        record.cert = b'0\x82\x04...'

        # Set cert field using Base64-encoded data:
        record.cert = "MIIE..."

        # Set cert field using PEM-encoded data:
        record.cert = "-----BEGIN CERTIFICATE-----\nMIIE..."

    On performing ``record.commit_changes()``, the certificate will be saved to the database using the Base64
    representation (without the PEM header and footer), i.e., ``"MIIE..."``.

    Example 2
    ---------

    You may also use the Certificate type's casting functionality outside a model by using the ``cast`` method directly::

        # If ``certificate`` is of type ``cryptography.x509.Certificate`, casting it returns it unchanged:
        cert = Certificate().cast(certificate)

        # Converts DER binary certificate data to ``cryptography.x509.Certificate`:
        cert = Certificate().cast(b'0\x82\x04...')

        # Converts Base64-encoded certificate data to ``cryptography.x509.Certificate`:
        cert = Certificate().cast("MIIE...")

        # Converts PEM-encoded certificate data to ``cryptography.x509.Certificate`:
        cert = Certificate().cast("-----BEGIN CERTIFICATE-----\nMIIE...")
    """

    def __init__(self):
        self._type_engine = Text

    def cast(self, value):
        """Tries to interpret the given value as an X.509 certificate and convert it to an
        `cryptography.x509.Certificate` object. Values which do not require conversion are returned unchanged.

        :param value: The value to convert (may be in DER, Base64(DER), or PEM format)

        :raises: :class:`TypeError`: ``value`` is of an unexpected data type
        :raises: :class:`ValueError`: ``value`` does not contain data which is interpretable as a certificate

        :returns: A ``cryptography.x509.Certificate`` object or None if an empty value is given
        """

        if not value:
            return None

        elif isinstance(value, cryptography.x509.Certificate):
            return value

        elif isinstance(value, bytes):
            try:
                return cert_utils.x509_der_cert(value)
            except (binascii.Error, PyAsn1Error, SubstrateUnderrunError) as err:
                raise ValueError(
                    f"value cast to certificate appears DER encoded but cannot be deserialized as such: '{value}'"
                ) from err

        elif isinstance(value, str) and value.startswith("-----BEGIN CERTIFICATE-----"):
            try:
                return cert_utils.x509_pem_cert(value)
            except (PyAsn1Error, SubstrateUnderrunError) as err:
                raise ValueError(
                    f"value cast to certificate appears PEM encoded but cannot be deserialized as such: '{value}'"
                ) from err

        elif isinstance(value, str):
            try:
                return cert_utils.x509_der_cert(base64.b64decode(value, validate=True))
            except (binascii.Error, PyAsn1Error, SubstrateUnderrunError) as err:
                raise ValueError(
                    f"value cast to certificate appears Base64 encoded but cannot be deserialized as such: '{value}'"
                ) from err

        else:
            raise TypeError(
                f"value cast to certificate is of type '{value.__class__.__name__}' but should be one of 'str', "
                f"'bytes' or 'cryptography.x509.Certificate': '{value}'"
            )

    def generate_error_msg(self, value):
        return "must be a valid X.509 certificate encoded using Base64"

    def _dump(self, value):
        # Cast incoming value to Certificate object
        cert = self.cast(value)

        if not cert:
            return None

        # Save as Base64-encoded value (without the PEM "BEGIN" and "END" header/footer for efficiency)
        return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("utf-8")

    def render(self, value):
        # Cast value to Certificate object
        cert = self.cast(value)

        if not cert:
            return None

        # Render certificate in PEM format
        return cert.public_bytes(Encoding.PEM).decode("utf-8")
