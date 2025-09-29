import base64
import binascii
import io
from typing import Optional, TypeAlias, Union

import cryptography.x509
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.codec.der import decoder as pyasn1_decoder
from pyasn1.codec.der import encoder as pyasn1_encoder
from pyasn1.error import PyAsn1Error
from pyasn1_modules import pem as pyasn1_pem
from pyasn1_modules import rfc2459 as pyasn1_rfc2459
from sqlalchemy.types import Text

from keylime.certificate_wrapper import CertificateWrapper, wrap_certificate
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

        # If ``certificate`` is of type ``cryptography.x509.Certificate``, casting it returns it unchanged:
        cert = Certificate().cast(certificate)

        # Converts DER binary certificate data to ``cryptography.x509.Certificate``:
        cert = Certificate().cast(b'0\x82\x04...')

        # Converts Base64-encoded certificate data to ``cryptography.x509.Certificate``:
        cert = Certificate().cast("MIIE...")

        # Converts PEM-encoded certificate data to ``cryptography.x509.Certificate``:
        cert = Certificate().cast("-----BEGIN CERTIFICATE-----\nMIIE...")
    """

    IncomingValue: TypeAlias = Union[cryptography.x509.Certificate, CertificateWrapper, bytes, str, None]

    def __init__(self) -> None:
        super().__init__(Text)

    def _load_der_cert(self, der_cert_data: bytes) -> CertificateWrapper:
        """Loads a binary x509 certificate encoded using ASN.1 DER as a ``CertificateWrapper`` object. This
        method does not require strict adherence to ASN.1 DER thereby making it possible to accept certificates which do
        not follow every detail of the spec (this is the case for a number of TPM certs) [1,2].

        It achieves this by first using the strict parser provided by python-cryptography. If that fails, it decodes the
        certificate and re-encodes it using the more-forgiving pyasn1 library. The re-encoded certificate is then
        re-parsed by python-cryptography. For malformed certificates requiring re-encoding, the original bytes are
        preserved in the wrapper to maintain signature validity.

        This method is equivalent to the ``cert_utils.x509_der_cert`` function but does not produce a warning when the
        backup parser is used, allowing this condition to be optionally detected and handled by the model where
        relevant. This is part of the fix for issue 1559 [3].

        Note: This method is marked as protected as ``self.cast(...)`` should be called from outside the class instead.

        [1] https://github.com/keylime/keylime/issues/944
        [2] https://github.com/pyca/cryptography/issues/7189
        [3] https://github.com/keylime/keylime/issues/1559

        :param der_cert_data: the DER bytes of the certificate

        :raises: :class:`SubstrateUnderrunError`: cert could not be deserialized even using the fallback pyasn1 parser

        :returns: A ``CertificateWrapper`` object
        """

        try:
            cert = cryptography.x509.load_der_x509_certificate(der_cert_data)
            return wrap_certificate(cert, None)
        except Exception:
            pyasn1_cert = pyasn1_decoder.decode(der_cert_data, asn1Spec=pyasn1_rfc2459.Certificate())[0]
            cert = cryptography.x509.load_der_x509_certificate(pyasn1_encoder.encode(pyasn1_cert))
            # Preserve the original bytes when re-encoding is necessary
            return wrap_certificate(cert, der_cert_data)

    def _load_pem_cert(self, pem_cert_data: str) -> CertificateWrapper:
        """Loads a text x509 certificate encoded using PEM (Base64ed DER with header and footer) as a
        ``CertificateWrapper`` object. This method does not require strict adherence to ASN.1 DER thereby
        making it possible to accept certificates which do not follow every detail of the spec (this is the case for
        a number of TPM certs) [1,2].

        It achieves this by first using the strict parser provided by python-cryptography. If that fails, it decodes the
        certificate and re-encodes it using the more-forgiving pyasn1 library. The re-encoded certificate is then
        re-parsed by python-cryptography. For malformed certificates requiring re-encoding, the original DER bytes are
        preserved in the wrapper to maintain signature validity.

        This method is equivalent to the ``cert_utils.x509_der_cert`` function but does not produce a warning when the
        backup parser is used, allowing this condition to be optionally detected and handled by the model where
        relevant. This is part of the fix for issue 1559 [3].

        Note: This method is marked as protected as ``self.cast(...)`` should be called from outside the class instead.

        [1] https://github.com/keylime/keylime/issues/944
        [2] https://github.com/pyca/cryptography/issues/7189
        [3] https://github.com/keylime/keylime/issues/1559

        :param pem_cert_data: the PEM text of the certificate

        :raises: :class:`SubstrateUnderrunError`: cert could not be deserialized even using the fallback pyasn1 parser

        :returns: A ``CertificateWrapper`` object
        """

        try:
            cert = cryptography.x509.load_pem_x509_certificate(pem_cert_data.encode("utf-8"))
            return wrap_certificate(cert, None)
        except Exception:
            der_data = pyasn1_pem.readPemFromFile(io.StringIO(pem_cert_data))
            pyasn1_cert = pyasn1_decoder.decode(der_data, asn1Spec=pyasn1_rfc2459.Certificate())[0]
            cert = cryptography.x509.load_der_x509_certificate(pyasn1_encoder.encode(pyasn1_cert))
            # Only preserve original bytes if we have valid DER data
            original_bytes = der_data if isinstance(der_data, bytes) and der_data else None
            # Preserve the original bytes when re-encoding is necessary
            return wrap_certificate(cert, original_bytes)

    def infer_encoding(self, value: IncomingValue) -> Optional[str]:
        """Tries to infer the certificate encoding from the given value based on the data type and other surface-level
        checks. Whatever the encoding inferred, it is not guaranteed that the value is a valid certificate which will
        be successfully deserialized.

        :param value: The value in DER, Base64(DER), or PEM format (or an already deserialized certificate object)

        :returns: ``"der"`` when the value appears to be DER encoded
        :returns: ``"pem"`` when the value appears to be PEM encoded
        :returns: ``"base64"`` when the value appears to be Base64(DER) encoded (without PEM headers)
        :returns: ``"wrapped"`` when the value is already a ``CertificateWrapper`` object
        :returns: ``"decoded"`` when the value is already a ``cryptography.x509.Certificate`` object
        :returns: ``"disabled"`` when the value is the string "disabled"
        :returns: ``None`` when the encoding cannot be inferred
        """
        # pylint: disable=no-else-return

        if isinstance(value, CertificateWrapper):
            return "wrapped"
        elif isinstance(value, cryptography.x509.Certificate):
            return "decoded"
        elif isinstance(value, bytes):
            return "der"
        elif isinstance(value, str) and value == "disabled":
            return "disabled"
        elif isinstance(value, str) and value.startswith("-----BEGIN CERTIFICATE-----"):
            return "pem"
        elif isinstance(value, str):
            return "base64"
        else:
            return None

    def asn1_compliant(self, value: IncomingValue) -> Optional[bool]:
        """Checks whether a value can be deserialized by python-cryptography. As the library enforces strict
        adherence to the ASN.1 Distinguished Encoding Rules (DER), this method returns ``False`` whenever an
        incoming value is not a valid certificate which conforms to ASN.1 DER.

        Note: ``self.cast(...)`` and related methods in this class will not necessarily fail if this method returns
        ``False``. They will first attempt to re-encode the certificate using a more forgiving ASN.1 library, as there
        are many certificates "in the wild" which are not strictly compliant [1, 2].

        [1] https://github.com/keylime/keylime/issues/944
        [2] https://github.com/pyca/cryptography/issues/7189

        :param value: The value in DER, Base64(DER), or PEM format (or an already deserialized certificate object)

        :returns: ``"True"`` if the value can be deserialized by python-cryptography and is ASN.1 DER compliant
        :returns: ``"True"`` if the value is the string "disabled" (considered compliant as it's a valid field value)
        :returns: ``"False"`` if the value cannot be deserialized by python-cryptography
        :returns: ``None`` if the value is already a deserialized certificate of type ``cryptography.x509.Certificate``
        """

        try:
            match self.infer_encoding(value):
                case "wrapped":
                    # For CertificateWrapper objects, check if they have original bytes (indicating re-encoding was needed)
                    return not value.has_original_bytes  # type: ignore[union-attr]
                case "decoded":
                    return None
                case "disabled":
                    return True
                case "der":
                    cryptography.x509.load_der_x509_certificate(value)  # type: ignore[reportArgumentType, arg-type]
                case "pem":
                    cryptography.x509.load_pem_x509_certificate(value.encode("utf-8"))  # type: ignore[reportArgumentType, arg-type, union-attr]
                case "base64":
                    der_value = base64.b64decode(value, validate=True)  # type: ignore[reportArgumentType, arg-type]
                    cryptography.x509.load_der_x509_certificate(der_value)
                case _:
                    raise Exception
        except Exception:
            return False

        return True

    def cast(self, value: IncomingValue) -> Optional[CertificateWrapper]:
        """Tries to interpret the given value as an X.509 certificate and convert it to a
        ``CertificateWrapper`` object. Values which do not require conversion are returned unchanged.

        :param value: The value to convert (may be in DER, Base64(DER), or PEM format)

        :raises: :class:`TypeError`: ``value`` is of an unexpected data type
        :raises: :class:`ValueError`: ``value`` does not contain data which is interpretable as a certificate

        :returns: A ``CertificateWrapper`` object or None if an empty value is given
        """

        if not value:
            return None

        match self.infer_encoding(value):
            case "wrapped":
                return value  # type: ignore[return-value]
            case "decoded":
                # Wrap raw cryptography certificate without original bytes
                return wrap_certificate(value, None)  # type: ignore[arg-type]
            case "der":
                try:
                    return self._load_der_cert(value)  # type: ignore[reportArgumentType, arg-type]
                except PyAsn1Error as err:
                    raise ValueError(
                        f"value cast to certificate appears DER encoded but cannot be deserialized as such: {value!r}"
                    ) from err
            case "pem":
                try:
                    return self._load_pem_cert(value)  # type: ignore[reportArgumentType, arg-type]
                except PyAsn1Error as err:
                    raise ValueError(
                        f"value cast to certificate appears PEM encoded but cannot be deserialized as such: "
                        f"'{str(value)}'"
                    ) from err
            case "base64":
                try:
                    return self._load_der_cert(base64.b64decode(value, validate=True))  # type: ignore[reportArgumentType, arg-type]
                except (binascii.Error, PyAsn1Error) as err:
                    raise ValueError(
                        f"value cast to certificate appears Base64 encoded but cannot be deserialized as such: "
                        f"'{str(value)}'"
                    ) from err
            case _:
                raise TypeError(
                    f"value cast to certificate is of type '{value.__class__.__name__}' but should be one of 'str', "
                    f"'bytes' or 'cryptography.x509.Certificate': '{str(value)}'"
                )

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be a valid X.509 certificate in PEM format or otherwise encoded using Base64"

    def _dump(self, value: IncomingValue) -> Optional[str]:
        # Cast incoming value to Certificate object
        cert = self.cast(value)

        if not cert:
            return None

        return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("utf-8")

    def render(self, value: IncomingValue) -> Optional[str]:
        # Cast value to Certificate object
        cert = self.cast(value)

        if not cert:
            return None

        return cert.public_bytes(Encoding.PEM).decode("utf-8")  # type: ignore[no-any-return]

    @property
    def native_type(self) -> type:
        return CertificateWrapper
