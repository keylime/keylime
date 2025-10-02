from types import MappingProxyType
from collections.abc import Mapping

from keylime.web.base.api_messages.api_message_helpers import APIMessageHelpers
from keylime.web.base.exceptions import InvalidMember


class APILink:
    @classmethod
    def load(cls, name, data):
        return cls(name, data)

    def __init__(self, name, href):
        if not APIMessageHelpers.is_valid_name(name):
            raise InvalidMember("link name is not a valid JSON:API member name")

        self._name = name
        self._href = None

        self.set_href(href)

        # JSON:API features not currently implemented:
        #   - "rel" member
        #   - "describedby" member
        #   - "title" member
        #   - "type" member
        #   - "hreflang" member
        #   - "meta" member

    def set_href(self, href):
        if not href:
            raise InvalidMember("link href must not be empty")

        if not isinstance(href, str):
            raise InvalidMember("link href added to JSON:API 'links' member must be a string")

        self._href = href
        return self

    def render(self):
        return self.href

    @property
    def name(self):
        return self._name

    @property
    def href(self):
        return self._href


class APILinksMixin:
    def add_link(self, link):
        if not isinstance(link, APILink):
            raise TypeError(f"cannot add item of type '{link.__class__.__name__}' to JSON:API 'links' member")

        if link.name in self._links:
            raise KeyError(f"link '{link.name}' already exists in JSON:API 'links' member")

        self._links[link.name] = link
        return self

    def load_links(self, data):
        if not isinstance(data, Mapping):
            raise TypeError("object loaded as JSON:API 'links' member must be a dict") 

        for name, value in data.items():
            link = APILink.load(name, value)
            self.add_link(link)

        return self

    def remove_link(self, name):
        if name not in self._links:
            raise KeyError(f"link '{name}' does not exist in JSON:API 'links' member")

        del self._link[name]
        return self

    def clear_links(self):
        self._links.clear()
        return self

    def render_links(self):
        return { name: link.render() for name, link in self.links.items() }

    @property
    def links(self):
        return MappingProxyType(self._links)