import re
from types import MappingProxyType

from keylime.web.base.errors import InvalidMessage, UnexpectedMember, InvalidMember, MultipleResourceAccessError


class APIMessageBody:

    MEMBER_NAME_REGEX = re.compile("^(@|[a-zA-Z0-9]+:)?[a-zA-Z0-9](?:[a-zA-Z0-9-_]*[a-zA-Z0-9])?$")

    @staticmethod
    def is_valid_name(name):
        """Checks whether the given value adheres to the rules of JSON:API member names.

        See https://jsonapi.org/format/#document-member-names
        """

        if not isinstance(name, str):
            return False

        return bool(APIMessageBody.MEMBER_NAME_REGEX.match(name))

    def __init__(self, data=None, errors=None, meta=None, links=None, **kwargs):
        if data and errors:
            raise InvalidMessage("both 'data' and 'errors' given for a JSON:API message body (only one is permitted)")

        if kwargs:
            raise UnexpectedMember(f"unexpected members given for a JSON:API message body: {list(kwargs.keys())}")

        self._data = None
        self._errors = []
        self._meta = {}
        self._links = {}
        self._jsonapi = APIInfo()

        if data:
            self.set_data(data)

        # TODO: handle errors
        # if errors:
        #     self.set_errors(data)

        if meta:
            self.set_meta(data)

        if links:
            self.set_links(links)
        
        # JSON:API features not currently implemented:
        #   - "included" member
        #   - link objects in the "links" field

    def add_resource(self, resource):
        if not isinstance(resource, (APIResource, dict)):
            raise InvalidMember("resource added to JSON:API 'data' member must be an APIResource object or a dict")

        if isinstance(resource, dict):
            resource = APIResource(**resource)

        if self._data is None:
            self._data = resource
            return

        if isinstance(self._data, APIResource):
            self._data = APIResourceList([self._data])

        if resource in self._data:
            raise InvalidMessage("resource already exists in JSON:API 'data' member")

        if any(res.id == resource.id and res.type == resource.type for res in self._data):
            raise InvalidMessage(
                f"resource with id '{resource.id}' and type '{resource.type}' already exists in JSON:API 'data' member"
            )

        self._data.append(resource)

    def remove_resource(self, resource):
        if resource not in self._data:
            raise KeyError("resource does not exist in JSON:API 'data' member")

        self._data.remove(resource)

        if not self._data:
            self._data = None

    def set_data(self, data):
        if not isinstance(data, (APIResource, dict, list, tuple)):
            raise InvalidMember("the JSON:API 'data' member must be an APIResource, dict, list or tuple")

        if isinstance(data, dict):
            data = APIResource(**data)

        if isinstance(data, APIResource):
            self._data = data
            return

        self._data = APIResourceList()

        for item in data:
            self.add_resource(item)

        if not isinstance(self._data, APIResourceList):
            self._data = APIResourceList([self._data])

    def clear_data(self):
        self._data = None

    def add_meta(self, field, value):
        if not APIMessageBody.is_valid_name(field):
            raise InvalidMember(f"field name '{field}' added to JSON:API 'meta' member is not valid")

        if not isinstance(value, (dict, list, tuple, str, int, float, bool)) and not None:
            raise InvalidMember("value added to JSON:API 'meta' member is not serialisable to JSON")

        if field in self._meta:
            raise KeyError(f"field '{field}' already exists in JSON:API 'meta' member")

        self._meta[field] = value

    def remove_meta(self, field):
        if field not in self._meta:
            raise KeyError(f"field '{field}' does not exist in JSON:API 'meta' member")

        del self._meta[field]

    def set_meta(self, meta):
        if not isinstance(meta, dict):
            raise InvalidMember("the JSON:API 'meta' member must be serialisable to a JSON object")

        self._meta = {}

        for field, value in meta.items():
            self.add_meta(field, value)

    def clear_meta(self):
        self._meta = {}

    def add_link(self, name, href):
        if not APIMessageBody.is_valid_name(name):
            raise InvalidMember("link name added to JSON:API 'links' member is not valid")

        if not isinstance(href, str):
            raise InvalidMember("link href added to JSON:API 'links' member must be a string")

        if name in self._links:
            raise KeyError(f"link '{name}' already exists in JSON:API 'links' member")

        self._links[name] = href

    def remove_link(self, name):
        if name not in self._links:
            raise KeyError(f"link '{name}' does not exist in JSON:API 'links' member")

        del self._link[name]

    def set_links(self, links):
        if not isinstance(links, dict):
            raise InvalidMember("the JSON:API 'links' member must be serialisable to a JSON object")

        self._links = {}

        for name, value in links.items():
            self.add_link(name, value)

    def clear_links(self):
        self._links = {}

    def check_validity(self):
        if not self._data and not self._errors and not self._meta:
            raise InvalidMessage(
                "none of 'data', 'errors' or 'meta' is given for a JSON:API resource (at least one is required)"
            )

    def render(self):
        self.check_validity()

        output = {}

        if self.data:
            output["data"] = self.data.render()

        if self.errors:
            output["errors"] = self.errors

        if self.meta:
            output["meta"] = self._meta.copy()

        if self.links:
            output["links"] = self._links.copy()

        if self.jsonapi:
            output["jsonapi"] = self.jsonapi.render()

        return output

    @property
    def data(self):
        if isinstance(self._data, (dict, list)):
            return self._data.copy()
        else:
            return self._data

    @property
    def errors(self):
        return self._errors.copy()

    @property
    def meta(self):
        return MappingProxyType(self._meta)

    @property
    def links(self):
        return MappingProxyType(self._links)

    @property
    def jsonapi(self):
        return self._jsonapi


class APIResource:

    def __init__(self, type=None, id=None, attributes=None, links=None, meta=None):
        if not type:
            raise InvalidMessage("no 'type' given for a JSON:API resource")

        if type and not APIMessageBody.is_valid_name(type):
            raise InvalidMember("invalid 'type' given for a JSON:API resource")

        if id and not isinstance(id, str):
            raise InvalidMember("the 'id' of a JSON:API resource must be a string")

        self._type = type or None
        self._id = id or None
        self._attributes = {}
        self._links = {}
        self._meta = {}

        if attributes:
            self.set_attributes(attributes)

        if links:
            self.set_links(links)

        if meta:
            self.set_meta(meta)

        # JSON:API features not currently implemented:
        #   - "relationships" member
        #   - "lid" member
        #   - link objects in the "links" field

    def set_type(self, type):
        if not APIMessageBody.is_valid_name(type):
            raise InvalidMember("invalid 'type' given for a JSON:API resource")

        self._type = type

    def set_id(self, id_):
        if not isinstance(id_, str):
            raise InvalidMember("the 'id' of a JSON:API resource must be a string")

        if not id_:
            raise InvalidMember("cannot set 'id' of JSON:API resource to an empty value")

        self._id = id_

    def clear_id(self):
        self._id = None

    def add_attribute(self, name, value):
        if not APIMessageBody.is_valid_name(name):
            raise InvalidMember("attribute name added to JSON:API resource is not valid")

        if not isinstance(value, (dict, list, tuple, str, int, float, bool)) and not None:
            raise InvalidMember("attribute value added to JSON:API resource is not serialisable to JSON")

        if name in self._attributes:
            raise KeyError(f"attribute '{name}' already exists in JSON:API resource")

        self._attributes[name] = value

    def remove_attribute(self, name):
        if name not in self._attributes:
            raise KeyError(f"attribute '{name}' does not exist in JSON:API resource")

        del self._attributes[name]

    def set_attributes(self, attributes):
        if not isinstance(attributes, dict):
            raise InvalidMember("the JSON:API 'attributes' member must be serialisable to a JSON object")

        self._attributes = {}

        for name, value in attributes.items():
            self.add_attribute(name, value)

    def clear_attributes(self):
        self._attributes = {}

    def add_meta(self, field, value):
        if not APIMessageBody.is_valid_name(type):
            raise InvalidMember("field name added to JSON:API 'meta' member is not valid")

        if not isinstance(value, (dict, list, tuple, str, int, float, bool)) and not None:
            raise InvalidMember("value added to JSON:API 'meta' member is not serialisable to JSON")

        if field in self._meta:
            raise KeyError(f"field '{field}' already exists in JSON:API 'meta' member")

        self._meta[field] = value

    def remove_meta(self, field):
        if field not in self._meta:
            raise KeyError(f"field '{field}' does not exist in JSON:API 'meta' member")

        del self._meta[field]

    def set_meta(self, meta):
        if not isinstance(data, dict):
            raise InvalidMember("the JSON:API 'meta' member must be serialisable to a JSON object")

        self._meta = {}

        for field, value in meta.items():
            self.add_meta(field, value)

    def clear_meta(self):
        self._meta = {}

    def add_link(self, name, href):
        if not APIMessageBody.is_valid_name(name):
            raise InvalidMember("link name added to JSON:API 'links' member is not valid")

        if not isinstance(href, str):
            raise InvalidMember("link href added to JSON:API 'links' member must be a string")

        if name in self._links:
            raise KeyError(f"link '{name}' already exists in JSON:API 'links' member")

        self._links[name] = href

    def remove_link(self, name):
        if name not in self._links:
            raise KeyError(f"link '{name}' does not exist in JSON:API 'links' member")

        del self._link[name]

    def set_links(self, links):
        if not isinstance(links, dict):
            raise InvalidMember("the JSON:API 'links' member must be serialisable to a JSON object")

        self._links = {}

        for name, value in links.items():
            self.add_link(name, value)

    def clear_links(self):
        self._links = {}

    def render(self):
        output = { "type": self.type }

        if self.id:
            output["id"] = self.id

        if self.attributes:
            output["attributes"] = self._attributes.copy()

        if self.links:
            output["links"] = self._links.copy()

        if self.meta:
            output["meta"] = self._meta.copy()

        return output

    @property
    def type(self):
        return self._type

    @property
    def id(self):
        return self._id

    @property
    def attributes(self):
        return MappingProxyType(self._attributes)

    @property
    def links(self):
        return MappingProxyType(self._links)

    @property
    def meta(self):
        return MappingProxyType(self._meta)


class APIResourceList(list):
    def _invalid_property_msg(self, prop):
        return f"a list of resources does not have a '{prop}' property"

    def render(self):
        output = []

        for item in self:
            output.append(item.render())

        return output

    @property
    def type(self):
        raise MultipleResourceAccessError(self._invalid_property_msg("type"))

    @property
    def id(self):
        raise MultipleResourceAccessError(self._invalid_property_msg("id"))

    @property
    def attributes(self):
        raise MultipleResourceAccessError(self._invalid_property_msg("attributes"))

    @property
    def links(self):
        raise MultipleResourceAccessError(self._invalid_property_msg("links"))

    @property
    def meta(self):
        raise MultipleResourceAccessError(self._invalid_property_msg("meta"))


class APIInfo:
    """Represents a JSON:API object which contains information about the JSON:API implementation.

    See https://jsonapi.org/format/#document-jsonapi-object
    """

    def __init__(self):
        self._ext = []
        self._profiles = []

    def add_ext(self, uri):
        self._ext.append(uri)

    def add_profile(self, uri):
        self._profiles.append(uri)

    def render(self):
        data = {}
        data["version"] = self.version

        if self.ext:
            data["ext"] = self.ext

        if self.profiles:
            data["profiles"] = self.profiles

        return data

    @property
    def version(self):
        return "1.1"

    @property
    def ext(self):
        return self._ext.copy()

    @property
    def profiles(self):
        return self._profiles.copy()

