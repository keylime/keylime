from types import MappingProxyType
from typing import overload

import keylime.web.base.api_messages as api_messages

from keylime.web.base.api_messages.api_message_helpers import APIMessageHelpers
from keylime.web.base.api_messages.api_links import APILink, APILinksMixin
from keylime.web.base.exceptions import MissingMember, InvalidMember


class APIError(APILinksMixin):
    @overload
    def __init__(self, api_code):
        ...
    @overload
    def __init__(self, api_code, http_code):
        ...
    @overload
    def __init__(self, api_code, detail):
        ...
    @overload
    def __init__(self, api_code, http_code, detail):
        ...
    def __init__(self, *args):
        if not args:
            raise MissingMember("the error code (i.e., 'api_code') of a JSON:API error must not be empty")

        if not APIMessageHelpers.is_valid_name(args[0]):
            raise InvalidMember("the given error code (i.e., 'api_code') is not a valid JSON:API member name")

        self._api_code = None
        self._http_code = None
        self._detail = None
        self._source = None
        self._links = {}

        self.set_api_code(args[0])

        match args[1:]:
            case ():
                pass
            case (http_code,) if isinstance(http_code, int):
                self.set_http_code(http_code)
            case (detail,) if isinstance(detail, str):
                self.set_detail(detail)
            case (http_code, detail):
                self.set_http_code(http_code)
                self.set_detail(detail)
            case _:
                raise TypeError(f"{self.__class__}() received invalid positional arguments")

        # JSON:API features not currently implemented:
        #   - "id" member
        #   - "title" member
        #   - "meta" member

    def set_api_code(self, api_code):
        if not APIMessageHelpers.is_valid_name(api_code):
            raise InvalidMember("invalid api_code given for a JSON:API error")

        if not self.http_code:
            if api_code == "not_found":
                self.set_http_code(404)
            elif api_code == "conflict":
                self.set_http_code(409)
            elif api_code == "invalid_resource_data":
                self.set_http_code(422)

        self._api_code = api_code
        return self

    def set_http_code(self, http_code):
        if not http_code:
            raise InvalidMember("the status code (i.e., 'http_code') of a JSON:API error must not be empty")

        if not isinstance(http_code, int):
            raise InvalidMember("the status code (i.e., 'http_code') of a JSON:API error must be given as an int")

        if http_code < 400 or http_code > 599:
            raise InvalidMember("the status code (i.e., 'http_code') of a JSON:API error must be in range 400-599")

        self._http_code = http_code
        return self

    def clear_http_code(self):
        self._http_code = None
        return self
    
    def set_detail(self, detail):
        if not isinstance(detail, str):
            raise InvalidMember("the description (i.e., 'detail') of a JSON:API error must be a str")

        if not detail:
            raise InvalidMember("the description (i.e., 'detail') of a JSON:API error must not be empty")

        self._detail = detail
        return self

    def clear_detail(self):
        self._detail = None
        return self

    def set_source(self, **kwargs):
        match kwargs:
            case {"pointer": _} | {"parameter": _} | {"header": _}:
                self._source = kwargs
                return self
            case _:
                raise TypeError(f"{self.__class__}.set_source() received invalid keyword arguments")

    def clear_source(self):
        self._source = None
        return self

    def include(self, *items):
        for item in items:
            if isinstance(item, APILink):
                self.add_link(item)
            else:
                raise TypeError(f"cannot add item of type '{item.__class__.__name__}' to JSON:API 'errors' member")

        return self

    def render(self):
        output = {}

        if self.http_code:
            output["status"] = str(self.http_code)

        output["code"] = self.api_code

        if self.detail:
            output["detail"] = self.detail

        if self.source:
            output["source"] = dict(self.source)

        if self.links:
            output["links"] = self.render_links()

        return output

    def send_via(self, controller, *, code=None, status=None, stop_action=True):
        api_messages.APIMessageBody(self).send_via(controller, code=code, status=status, stop_action=stop_action)

    @property
    def api_code(self):
        return self._api_code

    @property
    def http_code(self):
        return self._http_code

    @property
    def detail(self):
        return self._detail

    @property
    def source(self):
        return MappingProxyType(self._source) if self._source else None
