import json

from sqlalchemy.types import Text, TypeDecorator


class Dictionary(TypeDecorator):
    """The Dictionary class implements the SQLAlchemy type API (by inheriting from ``TypeDecorator`` and, in turn,
    ``TypeEngine``) to allow model fields to be declared as containing objects of type ``dict``. Such a field may be
    set to either (1) a string containing a JSON object or (2) a ``dict`` object which is representable as a JSON
    object. The incoming value is always cast to and kept in memory as a ``dict``. If saved to a database, the  ``dict``
    is converted to its JSON representation.

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

    You may also use the Dictionary type's casting functionality outside a model by using the ``cast`` static method::

        # Casting a ``dict`` which is representable as JSON returns it unchanged:
        kv_pairs = Dictionary.cast({"key": "value"})

        # Casting a ``str`` containing a JSON object returns a ``dict``:
        kv_pairs = Dictionary.cast('{"key": "value"}')
    """

    impl = Text
    cache_ok = True

    @staticmethod
    def cast(value):
        """Tries to convert the given value to a ``dict`` which is representable as a JSON object. Values which do not
        require conversion are returned unchanged.

        :param value: The value to convert (may be a ``str`` containing a JSON object or a ``dict``)

        :raises: :class:`TypeError`: ``value`` is not of type ``str`` or ``dict``
        :raises: :class:`ValueError`: ``value`` is of the correct type but cannot be represented as a JSON object

        :returns: A ``dict`` object which is JSON representable
        """

        if isinstance(value, dict):
            try:
                json.dumps(value)
            except TypeError:
                raise TypeError(f"'dict' object cast to dictionary contains values which aren't representable as JSON")

            return value

        elif isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                raise ValueError(f"string value cast to dictionary is not valid JSON: '{value}'")

            if not isinstance(value, dict):
                raise ValueError(f"string value cast to dictionary is not a valid JSON object: '{value}'")

            return value

        else:
            raise TypeError(
                f"value cast to dictionary is of type '{value.__class__.__name__}' but should either 'str' or "
                f"'dict': '{value}'"
            )

    def process_bind_param(self, value, dialect):
        """Prepares an incoming value representable as a JSON object for storage in a database. SQLAlchemy's
        ``TypeDecorator`` class uses this to construct the callables which are returned when
        ``self.bind_processor(dialect)`` or ``self.literal_processor(dialect)`` are called. These callables in turn are
        used to prepare the incoming value for inclusion within a SQL statement.

        When the Dictionary type is used in a model which is not database persisted, the callable returned by
        ``self.bind_processor(dialect)`` is still used to ensure that the data saved in the record is of the
        expected type and format.

        :param value: The value to prepare for database storage (a ``str`` containing a JSON object or a ``dict``)

        :raises: :class:`TypeError`: ``value`` is not of type ``str`` or ``dict``
        :raises: :class:`ValueError`: ``value`` is of the correct type but cannot be represented as a JSON object

        :returns: A string containing a JSON object
        """

        if not value:
            return None

        # Cast incoming value to dict object
        dictionary = Dictionary.cast(value)
        # Save in DB as JSON
        return json.dumps(dictionary)

    def process_result_value(self, value, dialect):
        """Prepares an outgoing JSON object fetched from a database. SQLAlchemy's ``TypeDecorator`` class uses this
        to construct the callable which is returned by ``self.result_processor(dialect)``. This callable in turn is
        used to instantiate a ``dict`` object from JSON data returned by a SQL query.

        When the Dictionary type is used in a model which is not database persisted, the callable returned by
        ``self.result_processor(dialect)`` is still called to ensure that the data saved in the record is of the
        expected type and format.

        :param value: The outgoing value retrieved from the database

        :raises: :class:`TypeError`: ``value`` is not of type ``str`` or ``dict``
        :raises: :class:`ValueError`: ``value`` is of the correct type but cannot be represented as a JSON object

        :returns: A ``dict`` object which is JSON representable
        """

        if not value:
            return None

        # Cast outgoing value from DB to dict object
        return Dictionary.cast(value)

    @property
    def type_mismatch_msg(self):
        """A read-only property used as the error message when a model field of type Dictionary is set to a value
        which is not representable as a JSON object. When operating in push mode, this message is returned in
        the HTTP response to signify that an invalid API request was made and provide guidance on how to correct it.

        :returns: A string containing the error message
        """

        return "must be a valid JSON object"
