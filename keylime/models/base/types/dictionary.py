import json
from typing import Optional, TypeAlias, Union

from sqlalchemy.types import Text

from keylime.models.base.type import ModelType


class Dictionary(ModelType):
    """The Dictionary class implements the model type API (by inheriting from ``ModelType``) to allow model fields to be
    declared as containing objects of type ``dict``. Such a field may be set to either (1) a string containing a JSON
    object or (2) a ``dict`` object which is representable as a JSON object. The incoming value is always cast to and
    kept in memory as a ``dict``. If saved to a database, the  ``dict`` is converted to its JSON representation.

    The schema of the backing database table is assumed to declare the dictionary-containing column as type ``"Text"``
    or comparable, in line with established Keylime convention. This is somewhat inefficient for database engines which
    have a native JSON database (like PostgreSQL), so we may wish to revisit this choice at a later date.

    Example 1
    ---------

    To use the Dictionary type, declare a model field as in the following example::

        class SomeModel(PersistableModel):
            def _schema(self):
                cls._field("kv_pairs", Dictionary, nullable=True)
                # (Any additional schema declarations...)

    Then, you can set the field by providing either a ``dict`` or a ``str``, as shown below::

        record = SomeModel.empty()

        # Set kv_pairs field using ``dict``:
        record.kv_pairs = {"key": "value"}

        # Set kv_pairs field using a ``str`` containing a JSON object:
        record.kv_pairs = '{"key": "value"}'

    On performing ``record.commit_changes()``, the dictionary will be saved to the database in its JSON representation.

    Example 2
    ---------

    You may also use the Dictionary type's casting functionality outside a model by using the ``cast`` method directly::

        # Casting a ``dict`` which is representable as JSON returns it unchanged:
        kv_pairs = Dictionary().cast({"key": "value"})

        # Casting a ``str`` containing a JSON object returns a ``dict``:
        kv_pairs = Dictionary().cast('{"key": "value"}')
    """

    IncomingValue: TypeAlias = Union[dict, str, None]

    def __init__(self) -> None:
        super().__init__(Text)

    def cast(self, value: IncomingValue) -> Optional[dict]:
        """Tries to convert the given value to a ``dict`` which is representable as a JSON object. Values which do not
        require conversion are returned unchanged.

        :param value: The value to convert (may be a ``str`` containing a JSON object or a ``dict``)

        :raises: :class:`TypeError`: ``value`` is of an unexpected data type
        :raises: :class:`ValueError`: ``value`` is of the correct type but cannot be represented as a JSON object

        :returns: A ``dict`` object which is JSON representable or None if an empty value is given
        """
        # Resolving the below pylint warning would negatively impact the readability of this method definition
        # pylint: disable=no-else-return

        if not value:
            return None

        elif isinstance(value, dict):
            try:
                json.dumps(value)
            except TypeError as err:
                raise TypeError(
                    "'dict' object cast to dictionary contains values which aren't representable as JSON"
                ) from err

            return value

        elif isinstance(value, str):
            try:
                dictionary = json.loads(value)
            except json.JSONDecodeError as err:
                raise ValueError(f"string value cast to dictionary is not valid JSON: '{value}'") from err

            if not isinstance(dictionary, dict):
                raise ValueError(f"string value cast to dictionary is not a valid JSON object: '{value}'")

            return dictionary

        else:
            raise TypeError(
                f"value cast to dictionary is of type '{value.__class__.__name__}' but should either 'str' or "
                f"'dict': '{value}'"
            )

    def generate_error_msg(self, _value: IncomingValue) -> str:
        return "must be a valid JSON object"

    def _dump(self, value: IncomingValue) -> Optional[str]:
        # Cast incoming value to dict object
        dictionary = self.cast(value)

        if not dictionary:
            return None

        # Save in DB as JSON
        return json.dumps(dictionary)

    @property
    def native_type(self) -> type:
        return dict
