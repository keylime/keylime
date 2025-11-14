from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from keylime.web.base.api_messages.api_message_helpers import APIMessageHelpers
from keylime.web.base.exceptions import InvalidMember


class APILink:
    @classmethod
    def load(cls, name: str, data: Any) -> "APILink":
        return cls(name, data)

    def __init__(self, name: str, href: str):
        if not APIMessageHelpers.is_valid_name(name):
            raise InvalidMember("link name is not a valid JSON:API member name")

        self._name = name
        self._href: str | None = None

        self.set_href(href)

        # JSON:API features not currently implemented:
        #   - "rel" member
        #   - "describedby" member
        #   - "title" member
        #   - "type" member
        #   - "hreflang" member
        #   - "meta" member

    def set_href(self, href: str) -> "APILink":
        if not href:
            raise InvalidMember("link href must not be empty")

        if not isinstance(href, str):
            raise InvalidMember("link href added to JSON:API 'links' member must be a string")

        self._href = href
        return self

    def render(self) -> str | None:
        return self.href

    @property
    def name(self) -> str:
        return self._name

    @property
    def href(self) -> str | None:
        return self._href


class APILinksMixin:
    _links: dict[str, APILink]

    def add_link(self, link: APILink) -> "APILinksMixin":
        if not isinstance(link, APILink):
            raise TypeError(f"cannot add item of type '{link.__class__.__name__}' to JSON:API 'links' member")

        if link.name in self._links:
            raise KeyError(f"link '{link.name}' already exists in JSON:API 'links' member")

        self._links[link.name] = link
        return self

    def load_links(self, data: Mapping[str, Any]) -> "APILinksMixin":
        if not isinstance(data, Mapping):
            raise TypeError("object loaded as JSON:API 'links' member must be a dict")

        for name, value in data.items():
            link = APILink.load(name, value)
            self.add_link(link)

        return self

    def remove_link(self, name: str) -> "APILinksMixin":
        if name not in self._links:
            raise KeyError(f"link '{name}' does not exist in JSON:API 'links' member")

        del self._links[name]
        return self

    def clear_links(self) -> "APILinksMixin":
        self._links.clear()
        return self

    def render_links(self) -> dict[str, str | None]:
        return {name: link.render() for name, link in self.links.items()}

    @property
    def links(self) -> MappingProxyType[str, APILink]:
        return MappingProxyType(self._links)
