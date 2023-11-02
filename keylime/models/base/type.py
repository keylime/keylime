from decimal import Decimal
from inspect import isclass
from numbers import Real
from typing import Any, TypeAlias, Union

from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.types import TypeEngine


class ModelType:
    """The ModelType class and its subclasses enable type declarations for fields in model schemas. When a model
    instance receives data from an external source, the incoming data is checked to be of the declared type for the
    field. If not, under certain circumstances, it may be cast to the declared type automatically. Similarly, when data
    is later read from that field to be used externally, it is prepared and formatted according to the context. The
    logic for these checks and conversions are contained in ModelType and its subclasses.

    Use of SQLAlchemy types
    -----------------------

    In many cases, when a field is declared, it is done so by specifying a SQLAlchemy type. For example, the ``"name"``
    field below is given the type of `String` which inherits from SQLAlchemy's `TypeEngine` class:

        def User(BasicModel):
            def _schema(cls):
                cls._field("name", String, nullable=True)
                # (Any additional schema declarations...)

    When this declaration is made, an instance of ModelType is transparently created by ``BasicModel`` and this is what
    is used to perform data conversion for the field, if necessary. Internally, ModelType understands that the "native
    type" for this field is `str`, i.e., that data for this field should be held in memory as a `str`. Any incoming data
    which is not a `str` or `None` will result in an error being generated for the ``"name"`` field.

    It is important to note the following caveats:

    * Any parameters passed to the SQLAlchemy ``TypeEngine`` when the field is declared are ignored by ModelType. So, if
    instead of the above declaration, ``"name"`` was declared with a type of ``String(50)``, the 50 character limit
    would not be enforced. Instead, the author of the ``User`` model should use the validation methods in `BasicModel`
    to impose a maximum length.

    * The base ModelType class performs minimal implicit conversion of data, so when using SQLAlchemy types as above,
    incoming data must typically already be in the correct "native type" or ``None``. Numeric SQLAlchemy types are a
    notable exception and will allow strings to be accepted so long as they are convertible to the equivalent Python
    type. Subclasses of ModelType (like ``Certificate``) often accept data in a variety of types and formats.

    * Although the case for most, only SQLAlchemy types with the ``python_type`` property may used in the above manner.
    When trying to use a SQLAlchemy type for which this is not the case, it is usually best to define a new custom type
    (as described below).

    Data lifecycle
    --------------

    Model data is processed according to the following diagram::

                                      db_input   ┌──────────────┐     ┌──────────────┐
                    ┌──────────────┐ ----------> │  SQLAlchemy  │ --> │   Database   │
           input    │              │ <---------- │  TypeEngine  │ <-- │    Engine    │
        ----------> │    Record    │  db_output  └──────────────┘     └──────────────┘
                    | (instance of |
        <---------- |    a model)  |  da_input   ┌─────────────────────┐
           output   |              | ----------> │ Durable Attestation │
                    └──────────────┘ <---------- │      Backend        │
                                      da_output  └─────────────────────┘

    When a field is set to a value (e.g., by calling ``record.change(field_name, value)``), an instance of ``ModelType``
    or a subclass receives ``input`` as an argument to ``type.cast()``. This method has the task of converting ``input``
    to the "native type" of the ``ModelType`` instance and the result is held in memory in the model instance.

    If the field is contained within a ``PersistableModel``, it may be written to a database (DB) or durable
    attestation (DA) backend. This is done by calling ``type.db_dump(value, dialect)`` or ``type.da_dump(value)`` which
    each produce ``db_input`` and ``da_input`` in the diagram. When these are later retrieved from the database or DA
    backend, they are ingested back into the model instance by calling ``type.db_load(value, dialect)`` or
    ``type.da_load(value)`` to produce ``db_output`` and ``da_output`` respectively.

    When a field is read from a model instance (to produce ``output`` in the diagram), this can happen in one of two
    ways. If the field is accessed directly (``record.field_name``) or obtained from one of ``record.values``,
    ``record.changes`` or ``record.record``, it is returned unchanged as it is stored in memory in the model instance.
    If instead data in the field is to be prepared for external use outside the application, this is done by calling
    ``type.render(value)``.

    Custom types
    ------------

    A custom type can be created by subclassing ``ModelType`` and overriding a number of its various methods. You can
    see examples of this in the ``Certificate`` and ``Dictionary`` classes found in ``keylime.models.base.types``.

    Typically, you will wish to provide your own implementation of `cast` at minimum. You may also optionally override
    each of ``db_dump``, ``da_dump``, ``db_load`` and ``da_load`` individually, but it is likely easier to just override
    ``_dump`` and ``_load`` which are called by the default implementations of the various public "dump" and "load"
    methods. In addition to these, you may also wish to override ``render`` if you need to prepare data in a particular
    format on its way out of the application. Whichever of these data lifecycle methods you override, note that your
    implementations must accept ``None`` as input (and, generally, return ``None`` in this case).

    To customise the error messages which BasicModel produces in the event of a type mismatch, you have the option of
    overriding ``generate_error_msg``. This method is called whenever a call to ``cast`` raises an error.

    Finally, you will typically want to set the ``_type_engine`` attribute to the SQLAlchemy ``TypeEngine`` you wish to
    use when persisting values of your custom type to the database (this is usually done in the ``__init__`` method). If
    you wish to use different SQLAlchemy types depending on the database engine being used (the SQLAlchemy "dialect"),
    you should instead set ``_type_engine`` to ``None`` and override the ``get_db_type`` method.
    """

    DeclaredTypeEngine: TypeAlias = Union[TypeEngine, type[TypeEngine]]

    def __init__(self, type_engine: DeclaredTypeEngine) -> None:
        if isclass(type_engine) and issubclass(type_engine, TypeEngine):
            self._type_engine = type_engine()
        elif isinstance(type_engine, TypeEngine):
            self._type_engine = type_engine
        else:
            raise TypeError(f"{self.__class__.__name__} must be initialised with a 'TypeEngine' class/object")

        try:
            self._type_engine.python_type
        except NotImplementedError:
            raise TypeError(
                f"{self._type_engine.__class__.__name__} does not define a 'python_type' property"
            ) from None

    def cast(self, value: Any) -> Any:
        if not value and isinstance(value, str):
            value = None

        if isinstance(value, str) and value.isnumeric() and issubclass(self.native_type, (Real, Decimal)):
            value = self.native_type(value)  # type: ignore

        if not isinstance(value, self.native_type) and value is not None:
            raise TypeError(f"value '{value}' was expected to be of type '{self.native_type.__name__}'")

        return value

    def generate_error_msg(self, _value: Any) -> str:
        return "is of an incorrect type"

    def render(self, value: Any) -> Any:
        value = self.cast(value)
        return value

    def _dump(self, value: Any) -> Any:
        value = self.cast(value)
        return value

    def _load(self, value: Any) -> Any:
        value = self.cast(value)
        return value

    def db_dump(self, value: Any, _dialect: Dialect) -> Any:
        return self._dump(value)

    def db_load(self, value: Any, _dialect: Dialect) -> Any:
        return self._load(value)

    def get_db_type(self, _dialect: Dialect) -> Any:
        return self._type_engine

    def da_dump(self, value: Any) -> Any:
        return self._dump(value)

    def da_load(self, value: Any) -> Any:
        return self._load(value)

    @property
    def native_type(self) -> type:
        return self._type_engine.python_type
