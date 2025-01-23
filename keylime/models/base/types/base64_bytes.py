import base64
import binascii
from typing import Optional, TypeAlias, Union

from sqlalchemy.types import Text

from keylime.models.base.type import ModelType


class Base64Bytes(ModelType):
    """The Base64Bytes class implements the model type API (by inheriting from
    ``ModelType``) to allow model fields to be declared as containing
    Base64-encoded strings. When such a field is set, the incoming value is
    decoded as appropriate and cast to an ``bytes`` object. If saved to a
    database, the object is encoded as a string using Base64.

    The schema of the backing database table is thus assumed to declare the
    column as type ``"Text"`` or comparable, in line with established Keylime
    convention.

    Example 1
    ---------

    To use the Base64Bytes type, declare a model field as in the following example::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("base64_field", Base64Bytes, nullable=True)
                # (Any additional schema declarations...)

    Then, you can set the field by providing:

    * a ``bytes`` object containing Base64-encoded string converted to bytes; or
    * a ``str`` object containing Base64 encoded string.

    This is shown in the code sample below::

        record = SomeModel.empty()

        # Set b64_str field using Base64-encoded binary data:
        record.b64_bytes = b'MIIE...'

        # Set b64_str field using Base64-encoded data:
        record.cert = "MIIE..."

    On performing ``record.commit_changes()``, the data will be saved to the
    database using the Base64-encoded string.

    Example 2
    ---------

    You may also use the Base64Bytes type's casting functionality outside a
    model by using the ``cast`` method directly::

        # In the special cases where the input string is a byte string
        # containing Base64-encoded data, Base64Bytes.cast() will try to decode
        # the cotent as UTF-8 encoded string, and then decode the resulting
        # Base64-encoded string
        b64_str = Base64Bytes().cast("b'MIIE...'")

        # Converts Base64-encoded string to bytes:
        b64_str = Base64Bytes().cast("MIIE...")
    """

    IncomingValue: TypeAlias = Union[bytes, str, None]

    def __init__(self) -> None:
        super().__init__(Text)

    def cast(self, value: IncomingValue) -> Optional[bytes]:
        """Tries to interpret the given value as a Base64-encoded string and
        convert it to a ``bytes`` object.

        :param value: The value to convert (Base64-encoded string)

        :raises: :class:`TypeError`: ``value`` is of an unexpected data type
        :raises: :class:`ValueError`: ``value`` does not contain data which is
        interpretable as a Base64-encoded data

        :returns: A ``bytes`` object or None if an empty value is given
        """

        if not value:
            return None

        if isinstance(value, str):
            try:
                return base64.b64decode(value, validate=True)  # type: ignore[reportArgumentType, arg-type]
            except binascii.Error as err:
                raise ValueError(
                    f"value appears Base64 encoded but cannot be deserialized as such: '{str(value)}'"
                ) from err
        if isinstance(value, bytes):
            try:
                s = value.decode("utf-8")
                return base64.b64decode(s, validate=True)  # type: ignore[reportArgumentType, arg-type]
            except binascii.Error as err:
                raise ValueError(
                    f"value appears Base64 encoded but cannot be deserialized as such: '{str(value)}'"
                ) from err
        else:
            raise TypeError(
                f"value cast to Base64 encoded 'bytes' is of type '{value.__class__.__name__}' but should be a 'str' or 'bytes': '{str(value)}'"
            )

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be a binary data or a valid Base64-encoded string"

    def _dump(self, value: IncomingValue) -> Optional[str]:
        if not value:
            return None

        # Save as Base64-encoded value
        return base64.b64encode(value).decode("utf-8")  # type: ignore[reportReturnType]

    def render(self, value: IncomingValue) -> Optional[str]:
        return self._dump(value)

    @property
    def native_type(self) -> type:
        return bytes
