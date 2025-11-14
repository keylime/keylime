from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, overload

import keylime.web.base.api_messages as api_messages  # pylint: disable=consider-using-from-import  # Avoid circular import
from keylime.web.base.api_messages.api_links import APILink, APILinksMixin
from keylime.web.base.api_messages.api_message_helpers import APIMessageHelpers
from keylime.web.base.api_messages.api_meta import APIMeta, APIMetaMixin
from keylime.web.base.exceptions import InvalidMember, MissingMember, UnexpectedMember

if TYPE_CHECKING:
    from keylime.web.base.controller import Controller


class APIResource(APILinksMixin, APIMetaMixin):
    @classmethod
    def load(cls, data: Mapping[str, Any]) -> "APIResource":
        if not isinstance(data, Mapping):
            raise InvalidMember(f"cannot load object of type '{data.__class__.__name__}' as JSON:API resource")

        data_dict = dict(data)  # type: ignore[assignment, attr-defined]
        resource = cls(data_dict.pop("type"))

        if data_dict.get("id"):
            resource.set_id(data_dict.pop("id"))

        if data_dict.get("attributes"):
            resource.load_attributes(data_dict.pop("attributes"))

        if data_dict.get("links"):
            resource.load_links(data_dict.pop("links"))

        if data_dict.get("meta"):
            resource.load_meta(data_dict.pop("meta"))

        if data_dict:
            raise UnexpectedMember(f"unexpected members given for a JSON:API resource: {list(data_dict.keys())}")

        return resource

    @overload
    def __init__(self, res_type: str) -> None:
        ...

    @overload
    def __init__(self, res_type: str, res_id: str) -> None:
        ...

    @overload
    def __init__(self, res_type: str, attributes: dict[str, Any]) -> None:
        ...

    @overload
    def __init__(self, res_type: str, res_id: str, attributes: dict[str, Any]) -> None:
        ...

    def __init__(self, *args: Any) -> None:  # type: ignore[misc]
        if not args:
            raise MissingMember("no 'type' given for a JSON:API resource")

        self._type: str | None = None
        self._id: str | None = None
        self._attributes: dict[str, Any] = {}
        self._links: dict[str, APILink] = {}
        self._meta: dict[str, APIMeta] = {}

        self.set_type(args[0])

        match args[1:]:
            case ():
                pass
            case (res_id,) if isinstance(res_id, str):
                self.set_id(res_id)
            case (attributes,) if isinstance(attributes, dict):
                self.load_attributes(attributes)
            case (res_id, attributes):
                self.load_attributes(attributes)
                self.set_id(res_id)
            case _:
                raise TypeError(f"{self.__class__}() received invalid positional arguments")

        # JSON:API features not currently implemented:
        #   - "relationships" member
        #   - "lid" member
        #   - link objects in the "links" field

    def set_type(self, res_type: str) -> "APIResource":
        if not APIMessageHelpers.is_valid_name(res_type):
            raise InvalidMember("invalid 'type' given for a JSON:API resource")

        self._type = res_type
        return self

    def set_id(self, res_id: str) -> "APIResource":
        if not isinstance(res_id, str):
            raise InvalidMember("the 'id' of a JSON:API resource must be a string")

        if not res_id:
            raise InvalidMember("cannot set 'id' of JSON:API resource to an empty value")

        self._id = res_id
        return self

    def clear_id(self) -> "APIResource":
        self._id = None
        return self

    def add_attribute(self, name: str, value: Any) -> "APIResource":
        if not APIMessageHelpers.is_valid_name(name):
            raise InvalidMember("attribute name added to JSON:API resource is not valid")

        if not isinstance(value, (dict, list, tuple, str, int, float, bool)):
            raise InvalidMember("attribute value added to JSON:API resource is not serialisable to JSON")

        if name in self._attributes:
            raise KeyError(f"attribute '{name}' already exists in JSON:API resource")

        self._attributes[name] = value
        return self

    def load_attributes(self, data: Mapping[str, Any]) -> "APIResource":
        if not isinstance(data, Mapping):
            raise TypeError("object loaded as JSON:API 'attributes' member must be a mapping")

        data_copy: dict[str, Any] = dict(data)  # Create mutable copy
        if data_copy.get("id"):
            self.set_id(data_copy.get("id"))  # type: ignore[arg-type]
            del data_copy["id"]

        for name, value in data_copy.items():
            self.add_attribute(name, value)

        return self

    def remove_attribute(self, name: str) -> "APIResource":
        if name not in self._attributes:
            raise KeyError(f"attribute '{name}' does not exist in JSON:API resource")

        del self._attributes[name]
        return self

    def clear_attributes(self) -> "APIResource":
        self._attributes.clear()
        return self

    def include(self, *items: APILink | APIMeta) -> "APIResource":
        for item in items:
            if isinstance(item, APILink):
                self.add_link(item)
            elif isinstance(item, APIMeta):
                self.add_meta(item)
            else:
                raise TypeError(f"cannot add item of type '{item.__class__.__name__}' to JSON:API 'errors' member")

        return self

    def render(self) -> dict[str, Any]:
        output: dict[str, Any] = {"type": self.type}

        if self.id:
            output["id"] = self.id

        if self.attributes:
            output["attributes"] = self._attributes.copy()

        if self.links:
            output["links"] = self.render_links()

        if self.meta:
            output["meta"] = self.render_meta()

        return output

    def send_via(
        self, controller: "Controller", *, code: int | None = None, status: str | None = None, stop_action: bool = True
    ) -> None:
        api_messages.APIMessageBody(self).send_via(controller, code=code, status=status, stop_action=stop_action)

    @property
    def type(self) -> str | None:
        return self._type

    @property
    def id(self) -> str | None:
        return self._id

    @property
    def attributes(self) -> MappingProxyType[str, Any]:
        return MappingProxyType(self._attributes)
