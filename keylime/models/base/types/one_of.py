from collections import Counter
from decimal import Decimal
from inspect import isclass
from numbers import Real

from sqlalchemy.types import Float, Integer, Numeric, String, TypeEngine

from keylime.models.base.errors import FieldDefinitionInvalid
from keylime.models.base.type import ModelType


class OneOf(ModelType):
    def __init__(self, *args):
        self._permitted = []

        for item in args:
            if isinstance(item, (str, Real, Decimal)):
                self._permitted.append(item)
            elif isinstance(item, ModelType):
                self._permitted.append(item)
            elif isclass(item) and issubclass(item, ModelType):
                self._permitted.append(item())  # type: ignore
            elif isinstance(item, TypeEngine) or (isclass(item) and issubclass(item, TypeEngine)):
                self._permitted.append(ModelType(type))
            else:
                raise FieldDefinitionInvalid("field defined with invalid 'OneOf' construct")

    def cast(self, value):
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.cast(value)
                except:
                    continue
            elif value == item:
                return value

        raise TypeError("value is not allowable by 'OneOf' definition")

    def generate_error_msg(self, value):
        return "is not a permitted value"

    def db_dump(self, value, dialect):
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.db_dump(value, dialect)
                except:
                    continue
            elif value == item:
                return value
            else:
                raise TypeError("value is not allowable by 'OneOf' definition")

    def db_load(self, value, dialect):
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.db_load(value, dialect)
                except:
                    continue
            elif value == item:
                return value
            else:
                raise TypeError("value is not allowable by 'OneOf' definition")

    def _lowest_common_ancestor(self, list):
        counter = Counter()

        for item in list:
            if not isclass(item):
                item = item.__class__

            mro = item.mro()

            for cls in reversed(mro):
                counter[cls] += 1

        highest_count = next(iter(counter.values()))
        lca = None

        for cls, count in counter.items():
            if count == highest_count:
                lca = cls

        return lca

    def get_db_type(self, dialect):
        db_types = [item.get_db_type(dialect) for item in self._permitted if isinstance(item, ModelType)]
        lc_db_type = self._lowest_common_ancestor(db_types)

        if lc_db_type not in (None, TypeEngine, object):
            return lc_db_type()

        literals = [item for item in self._permitted if not isinstance(item, ModelType)]
        lc_lit_type = self._lowest_common_ancestor(literals)

        if isclass(lc_lit_type):
            if issubclass(lc_lit_type, str):
                return String()
            elif issubclass(lc_lit_type, int):
                return Integer()
            elif issubclass(lc_lit_type, float):
                return Float()
            elif issubclass(lc_lit_type, (Real, Decimal)):
                return Numeric()
            else:
                raise FieldDefinitionInvalid("field defined with invalid 'OneOf' construct")

    def da_dump(self, value):
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.da_dump(value)
                except:
                    continue
            elif value == item:
                return value
            else:
                raise TypeError("value is not allowable by 'OneOf' definition")

    def da_load(self, value):
        if value is None or value == "":
            return None

        for item in self._permitted:
            if isinstance(item, ModelType):
                try:
                    return item.da_load(value)
                except:
                    continue
            elif value == item:
                return value
            else:
                raise TypeError("value is not allowable by 'OneOf' definition")

    @property
    def permitted(self):
        return self._permitted.copy()

    @property
    def native_type(self):
        raise NotImplementedError
