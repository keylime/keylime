from inspect import isclass

from sqlalchemy.types import PickleType, TypeEngine

from keylime.models.base.errors import FieldDefinitionInvalid


class ModelField:
    _name: str
    _type: TypeEngine
    _nullable: bool

    def __init__(self, name, type, nullable=False):
        if isclass(type):
            type = type()

        self._name = name
        self._type = type
        self._nullable = nullable

        if not isinstance(type, TypeEngine):
            raise FieldDefinitionInvalid(
                f"field '{name}' cannot be defined with type '{type}' as this is not a SQLAlchemy datatype "
                f"inheriting from 'sqlalchemy.types.TypeEngine'"
            )

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self

        return obj.values.get(self._name)

    def __set__(self, obj, value):
        obj.change(self._name, value)

    def __delete__(self, obj):
        self.__set__(obj, None)

    @property
    def name(self):
        return self._name

    @property
    def type(self):
        return self._type

    @property
    def nullable(self):
        return self._nullable

    @property
    def python_type(self):
        try:
            return self.type.python_type
        except:
            return None
