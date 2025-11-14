from types import MappingProxyType
from typing import Any, Union

from keylime.web.base.api_messages.api_message_helpers import APIMessageHelpers
from keylime.web.base.exceptions import InvalidMember

MetaValue = Union[dict[str, Any], list[Any], tuple[Any, ...], str, int, float, bool, None]


class APIMeta:
    @classmethod
    def load(cls, name: str, data: Any) -> "APIMeta":
        return cls(name, data)

    def __init__(self, name: str, value: MetaValue):
        if not APIMessageHelpers.is_valid_name(name):
            raise InvalidMember(f"field name '{name}' added to JSON:API 'meta' member is not valid")

        self._name = name
        self._value: MetaValue = None

        self.set_value(value)

    def set_value(self, value: MetaValue) -> "APIMeta":
        if not isinstance(value, (dict, list, tuple, str, int, float, bool)):
            raise InvalidMember("value added to JSON:API 'meta' member is not serialisable to JSON")

        self._value = value
        return self

    def clear_value(self) -> "APIMeta":
        self._value = None
        return self

    def render(self) -> MetaValue:
        return self.value

    @property
    def name(self) -> str:
        return self._name

    @property
    def value(self) -> MetaValue:
        if isinstance(self._value, dict):
            return self._value.copy()
        if isinstance(self._value, list):
            return self._value.copy()
        return self._value


class APIMetaMixin:
    _meta: dict[str, APIMeta]

    def add_meta(self, meta: APIMeta) -> "APIMetaMixin":
        if not isinstance(meta, APIMeta):
            raise InvalidMember(f"cannot add item of type '{meta.__class__.__name__}' to JSON:API 'meta' member")

        if meta.name in self._meta:
            raise KeyError(f"field '{meta.name}' already exists in JSON:API 'meta' member")

        self._meta[meta.name] = meta
        return self

    def load_meta(self, data: dict[str, Any]) -> "APIMetaMixin":
        if not isinstance(data, dict):
            raise TypeError("object loaded as JSON:API 'meta' member must be a dict")

        for name, value in data.items():
            meta = APIMeta.load(name, value)
            self.add_meta(meta)

        return self

    def remove_meta(self, name: str) -> "APIMetaMixin":
        if name not in self._meta:
            raise KeyError(f"field '{name}' does not exist in JSON:API 'meta' member")

        del self._meta[name]
        return self

    def clear_meta(self) -> "APIMetaMixin":
        self._meta.clear()
        return self

    def render_meta(self) -> dict[str, MetaValue]:
        return {name: meta.render() for name, meta in self.meta.items()}

    @property
    def meta(self) -> MappingProxyType[str, APIMeta]:
        return MappingProxyType(self._meta)
