from inspect import isclass

from sqlalchemy.types import TypeEngine

from keylime.models.base.errors import FieldDefinitionInvalid
from keylime.models.base.type import ModelType


class ModelField:
    _name: str
    _type: ModelType
    _nullable: bool

    def __init__(self, name, type, nullable=False):
        self._name = name
        self._nullable = nullable

        if isinstance(type, ModelType):
            self._type = type
        elif isclass(type) and issubclass(type, ModelType):
            self._type = type()  # type: ignore
        elif isinstance(type, TypeEngine) or (isclass(type) and issubclass(type, TypeEngine)):
            self._type = ModelType(type)
        else:
            raise FieldDefinitionInvalid(
                f"field '{name}' cannot be defined with type '{type}' as this is neither a ModelType subclass/instance "
                f"nor a SQLAlchemy data type inheriting from 'sqlalchemy.types.TypeEngine'"
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
    def native_type(self):
        try:
            return self.type.native_type
        except:
            return None

    @property
    def nullable(self):
        return self._nullable
