from types import MappingProxyType

from keylime.web.base.api_messages.api_message_helpers import APIMessageHelpers
from keylime.web.base.exceptions import InvalidMember


class APIMeta:
    @classmethod
    def load(cls, name, data):
        return cls(name, data)

    def __init__(self, name, value):
        if not APIMessageHelpers.is_valid_name(name):
            raise InvalidMember(f"field name '{name}' added to JSON:API 'meta' member is not valid")

        self._name = name
        self._value = None

        self.set_value(value)

    def set_value(self, value):
        if not isinstance(value, (dict, list, tuple, str, int, float, bool)) and not None:
            raise InvalidMember("value added to JSON:API 'meta' member is not serialisable to JSON")

        self._value = value
        return self

    def clear_value(self):
        self._value = None
        return self

    def render(self):
        return self.value

    @property
    def name(self):
        return self._name

    @property
    def value(self):
        if isinstance(self._value, dict):
            return self._value.copy()
        elif isinstance(self._value, (list, tuple)):
            return self._value.copy()
        else:
            return self._value


class APIMetaMixin:
    def add_meta(self, meta):
        if not isinstance(meta, APIMeta):
            raise InvalidMember(f"cannot add item of type '{meta.__class__.__name__}' to JSON:API 'meta' member")

        if meta.name in self._meta:
            raise KeyError(f"field '{field}' already exists in JSON:API 'meta' member")

        self._meta[meta.name] = meta
        return self

    def load_meta(self, data):
        if not isinstance(data, dict):
            raise TypeError("object loaded as JSON:API 'meta' member must be a dict") 

        for name, value in data.items():
            meta = APIMeta.load(name, value)
            self.add_meta(meta)

        return self

    def remove_meta(self, name):
        if name not in self._meta:
            raise KeyError(f"field '{name}' does not exist in JSON:API 'meta' member")

        del self._meta[name]
        return self

    def clear_meta(self):
        self._meta.clear()
        return self

    def render_meta(self):
        return { name: meta.render() for name, meta in self.meta.items() }

    @property
    def meta(self):
        return MappingProxyType(self._meta)