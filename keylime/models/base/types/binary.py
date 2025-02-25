import base64
import binascii
from inspect import isclass
from typing import Any, Optional, TypeAlias, Union

from sqlalchemy.types import LargeBinary, String

from keylime.models.base.type import ModelType


class Binary(ModelType):
    """The Binary class implements the model type API (by inheriting from ``ModelType``) to allow model fields to be
    declared as containing arbitrary binary data. Such a field may be set to a ``bytes`` object or a string, the later
    of which must contain data which is either Base64 or hex encoded. The incoming value is always cast to and kept in
    memory as a ``bytes`` object.

    When a model is rendered as JSON, fields of type ``Binary`` are encoded using Base64.
    
    In a database, the object may be stored using the binary data type of the database engine (the default) or encoded
    using Base64 and stored as text.

    Backing Database Type
    ---------------------

    The output data type used when persisting to a database is configurable at time of declaration by providing the
    ``persist_as`` option. By default, this is set to the ``LargeBinary`` SQLAlchemy type which is the suggested data
    type for any new fields which store binary data.

    ``String`` may be used instead which will cause the data to be Base64-encoded before it is sent to the database
    engine. In such case, the schema of the backing database table is assumed to declare the respective column as type
    ``"Text"`` or comparable.

    Example 1
    ---------

    To use the ``Binary`` type, declare a model field as in the following example::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("quote", Binary, nullable=True)
                # (Any additional schema declarations...)

    Then, you can set the field by providing either a ``bytes`` or a ``str``, as shown below::

        record = SomeModel.empty()

        # Set quote field using ``bytes``:
        record.quote = b'\x03\xff...'

        # Set quote field using a Base64-encoded ``str``:
        record.kv_pairs = "A/8..."

        # Set quote field using a hex-encoded ``str`` (with or without "0x" prefix):
        record.kv_pairs = "03ff..."
        record.kv_pairs = "0x03ff..."

    On performing ``record.commit_changes()``, the database will receive the raw binary content of the field.

    Example 2
    ---------

    You may change the data type used to save the value to the database::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("quote", Binary(persist_as=String), nullable=True)
                # (Any additional schema declarations...)

    Then, on performing ``record.commit_changes()``, the value will be converted to its Base64 representation.

    Example 3
    ---------

    You may also use the ``Binary`` type's casting functionality outside a model by using the ``cast`` method directly::

        # Casting a ``bytes`` object returns it unchanged:
        quote = Binary().cast(b'\x03\xff...')

        # Casting a ``str`` object correctly encoded using Base64 or hex returns a ``bytes`` object:
        quote = Binary().cast("A/8...")
        quote = Binary().cast("03ff...")
        quote = Binary().cast("0x03ff...")
    """

    IncomingValue: TypeAlias = Union[bytes, str, None]

    def __init__(self, persist_as=LargeBinary) -> None:
        if not isinstance(persist_as, (LargeBinary, String)) and not issubclass(persist_as, (LargeBinary, String)):
            raise TypeError("field of type 'Binary' must have a persist_as value of type 'LargeBinary' or 'String'")

        if isclass(persist_as):
            persist_as = persist_as()

        super().__init__(persist_as)

    def cast(self, value: IncomingValue) -> Optional[bytes]:
        # pylint: disable=no-else-return

        if not value:
            return None

        elif isinstance(value, bytes):
            return value

        elif isinstance(value, str):
            try:
                return base64.b64decode(value, validate=True)
            except binascii.Error:
                pass

            if value.startswith("0x"):
                value = value[2:]

            try:
                return bytes.fromhex(value)
            except ValueError:
                raise ValueError(f"string value cast to binary is not valid base64 or hex: '{value}'") # pylint: disable=raise-missing-from

        else:
            raise TypeError(
                f"value cast to binary is of type '{value.__class__.__name__}' but should be either 'bytes' or "
                f"'str': '{value}'"
            )

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be valid binary"

    def _dump(self, value: IncomingValue) -> Optional[str | bytes]:
        # pylint: disable=no-else-return

        value = self.cast(value)

        if not value:
            return None

        # If the backing database type is a string, encode as base64, otherwise return the raw binary
        if isinstance(self._type_engine, String):
            return base64.b64encode(value).decode("utf-8")
        else:
            return value

    def render(self, value: Any) -> Any:
        value = self.cast(value)
        return base64.b64encode(value).decode("utf-8")

    @property
    def native_type(self) -> type:
        return bytes
