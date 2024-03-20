import base64
import binascii

import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.error import PyAsn1Error, SubstrateUnderrunError
from sqlalchemy.types import Text, TypeDecorator

from keylime import cert_utils


class Certificate(TypeDecorator):
    """The Certificate class implements the SQLAlchemy type API (by inheriting from ``TypeDecorator`` and, in turn,
    ``TypeEngine``) to allow model fields to be declared as containing objects of type
    ``cryptography.x509.Certificate``. When such a field is set, the incoming value is decoded as appropriate and cast
    to an ``cryptography.x509.Certificate`` object. If saved to a database, the object is converted to its DER
    representation and encoded as a string using Base64.

    The schema of the backing database table is thus assumed to declare the certificate-containing column as type
    ``"Text"`` or comparable, in line with established Keylime convention. This is somewhat inefficient, so we may wish
    to consider switching to ``"Blob"`` at some point such that certificates are saved to the database as byte strings
    instead.

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

    You may also use the Certificate type's casting functionality outside a model by using the ``cast`` static method::

        # If ``certificate`` is of type ``cryptography.x509.Certificate`, casting it returns it unchanged:
        cert = Certificate.cast(certificate)

        # Converts DER binary certificate data to ``cryptography.x509.Certificate`:
        cert = Certificate.cast(b'0\x82\x04...')

        # Converts Base64-encoded certificate data to ``cryptography.x509.Certificate`:
        cert = Certificate.cast("MIIE...")

        # Converts PEM-encoded certificate data to ``cryptography.x509.Certificate`:
        cert = Certificate.cast("-----BEGIN CERTIFICATE-----\nMIIE...")
    """

    impl = Text
    cache_ok = True

    @staticmethod
    def cast(value):
        """Tries to interpret the given value as an X.509 certificate and convert it to an
        `cryptography.x509.Certificate` object. Values which do not require conversion are returned unchanged.

        :param value: The value to convert (may be in DER, Base64(DER), or PEM format)

        :raises: :class:`TypeError`: ``value`` is not of type ``str``, ``bytes`` or ``cryptography.x509.Certificate``
        :raises: :class:`ValueError`: ``value`` does not contain data which is interpretable as a certificate

        :returns: A ``cryptography.x509.Certificate`` object
        """

        if isinstance(value, cryptography.x509.Certificate):
            return value

        elif isinstance(value, bytes):
            try:
                return cert_utils.x509_der_cert(value)
            except (binascii.Error, PyAsn1Error, SubstrateUnderrunError):
                raise ValueError(
                    f"value cast to certificate appears DER encoded but cannot be deserialized as such: '{value}'"
                )

        elif isinstance(value, str) and value.startswith("-----BEGIN CERTIFICATE-----"):
            try:
                return cert_utils.x509_pem_cert(value)
            except (PyAsn1Error, SubstrateUnderrunError):
                raise ValueError(
                    f"value cast to certificate appears PEM encoded but cannot be deserialized as such: '{value}'"
                )

        elif isinstance(value, str):
            try:
                return cert_utils.x509_der_cert(base64.b64decode(value, validate=True))
            except (binascii.Error, PyAsn1Error, SubstrateUnderrunError):
                raise ValueError(
                    f"value cast to certificate appears Base64 encoded but cannot be deserialized as such: '{value}'"
                )

        else:
            raise TypeError(
                f"value cast to certificate is of type '{value.__class__.__name__}' but should be one of 'str', "
                f"'bytes' or 'cryptography.x509.Certificate': '{value}'"
            )

    def process_bind_param(self, value, dialect):
        """Prepares incoming certificate data for storage in a database. SQLAlchemy's ``TypeDecorator`` class uses this
        to construct the callables which are returned when ``self.bind_processor(dialect)`` or
        ``self.literal_processor(dialect)`` are called. These callables in turn are used to prepare certificates
        for inclusion within a SQL statement.

        When the Certificate type is used in a model which is not database persisted, the callable returned by
        ``self.bind_processor(dialect)`` is still used to ensure that the data saved in the record is of the
        expected type and format.

        :param value: The value to prepare for database storage (may be in DER, Base64(DER), or PEM format)

        :raises: :class:`TypeError`: ``value`` is not of type ``str``, ``bytes`` or ``cryptography.x509.Certificate``
        :raises: :class:`ValueError`: ``value`` does not contain data which is interpretable as a certificate

        :returns: A string containing the Base64-encoded certificate
        """

        if not value:
            return None

        # Cast incoming value to Certificate object
        cert = Certificate.cast(value)
        # Save in DB as Base64-encoded value (without the PEM "BEGIN" and "END" header/footer for efficiency)
        return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("utf-8")

    def process_result_value(self, value, dialect):
        """Prepares outgoing certificate data fetched from a database. SQLAlchemy's ``TypeDecorator`` class uses this
        to construct the callable which is returned by ``self.result_processor(dialect)``. This callable in turn is
        used to instantiate a ``cryptography.x509.Certificate`` object from certificate data returned by a SQL query.

        When the Certificate type is used in a model which is not database persisted, the callable returned by
        ``self.result_processor(dialect)`` is still called to ensure that the data saved in the record is of the
        expected type and format.

        :param value: The outgoing value retrieved from the database

        :raises: :class:`TypeError`: ``value`` is not of type ``str``, ``bytes`` or ``cryptography.x509.Certificate``
        :raises: :class:`ValueError`: ``value`` does not contain data which is interpretable as a certificate

        :returns: A ``cryptography.x509.Certificate`` object
        """

        if not value:
            return None

        # Cast outgoing value from DB to Certificate object
        return Certificate.cast(value)

    @property
    def type_mismatch_msg(self):
        """A read-only property used as the error message when a model field of type Certificate is set to a value
        which is not interpretable as an X.509 certificate. When operating in push mode, this message is returned in
        the HTTP response to signify that an invalid API request was made and provide guidance on how to correct it.

        :returns: A string containing the error message
        """

        return "must be a valid binary X.509 certificate encoded using Base64"
