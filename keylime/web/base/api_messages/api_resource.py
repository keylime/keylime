from types import MappingProxyType
from typing import overload
from collections.abc import Mapping

import keylime.web.base.api_messages as api_messages

from keylime.web.base.api_messages.api_message_helpers import APIMessageHelpers
from keylime.web.base.api_messages.api_links import APILink, APILinksMixin
from keylime.web.base.api_messages.api_meta import APIMeta, APIMetaMixin
from keylime.web.base.exceptions import MissingMember, UnexpectedMember, InvalidMember


class APIResource(APILinksMixin, APIMetaMixin):
    @classmethod
    def load(cls, data):
        if not isinstance(data, Mapping):
            raise InvalidMember(f"cannot load object of type '{data.__class__.__name__}' as JSON:API resource")

        data = data.copy()
        resource = cls(data.pop("type"))

        if data.get("id"):
            resource.set_id(data.pop("id"))
        
        if data.get("attributes"):
            resource.load_attributes(data.pop("attributes"))

        if data.get("links"):
            resource.load_links(data.pop("links"))

        if data.get("meta"):
            resource.load_meta(data.pop("meta"))

        if data:
            raise UnexpectedMember(f"unexpected members given for a JSON:API resource: {list(data.keys())}")

        return resource

    @overload
    def __init__(self, res_type):
        ...
    @overload
    def __init__(self, res_type, res_id):
        ...
    @overload
    def __init__(self, res_type, attributes):
        ...
    @overload
    def __init__(self, res_type, res_id, attributes):
        ...
    def __init__(self, *args):
        if not args:
            raise MissingMember("no 'type' given for a JSON:API resource")

        self._type = None
        self._id = None
        self._attributes = {}
        self._links = {}
        self._meta = {}

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

    def set_type(self, res_type):
        if not APIMessageHelpers.is_valid_name(res_type):
            raise InvalidMember("invalid 'type' given for a JSON:API resource")

        self._type = res_type
        return self

    def set_id(self, res_id):
        if not isinstance(res_id, str):
            raise InvalidMember("the 'id' of a JSON:API resource must be a string")

        if not res_id:
            raise InvalidMember("cannot set 'id' of JSON:API resource to an empty value")

        self._id = res_id
        return self

    def clear_id(self):
        self._id = None
        return self

    def add_attribute(self, name, value):
        if not APIMessageHelpers.is_valid_name(name):
            raise InvalidMember("attribute name added to JSON:API resource is not valid")

        if not isinstance(value, (dict, list, tuple, str, int, float, bool)) and not None:
            raise InvalidMember("attribute value added to JSON:API resource is not serialisable to JSON")

        if name in self._attributes:
            raise KeyError(f"attribute '{name}' already exists in JSON:API resource")

        self._attributes[name] = value
        return self

    def load_attributes(self, data):
        if not isinstance(data, Mapping):
            raise TypeError("object loaded as JSON:API 'attributes' member must be a mapping")

        if data.get("id"):
            self.set_id(data.get("id"))
            del data["id"]

        for name, value in data.items():
            self.add_attribute(name, value)

        return self

    def remove_attribute(self, name):
        if name not in self._attributes:
            raise KeyError(f"attribute '{name}' does not exist in JSON:API resource")

        del self._attributes[name]
        return self

    def clear_attributes(self):
        self._attributes.clear()
        return self

    def include(self, *items):
        for item in items:
            if isinstance(item, APILink):
                self.add_link(item)
            elif isinstance(item, APIMeta):
                self.add_meta(item)
            else:
                raise TypeError(f"cannot add item of type '{item.__class__.__name__}' to JSON:API 'errors' member")

        return self

    def render(self):
        output = { "type": self.type }

        if self.id:
            output["id"] = self.id

        if self.attributes:
            output["attributes"] = self._attributes.copy()

        if self.links:
            output["links"] = self.render_links()

        if self.meta:
            output["meta"] = self.render_meta()

        return output

    def send_via(self, controller, *, code=None, status=None, stop_action=True):
        api_messages.APIMessageBody(self).send_via(controller, code=code, status=status, stop_action=stop_action)

    @property
    def type(self):
        return self._type

    @property
    def id(self):
        return self._id

    @property
    def attributes(self):
        return MappingProxyType(self._attributes)