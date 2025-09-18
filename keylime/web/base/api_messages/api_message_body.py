from types import MappingProxyType
from collections.abc import Mapping, Sequence
from functools import reduce

import keylime.web.base as base
import keylime.web.base.api_messages as api_messages

from keylime import keylime_logging
from keylime.web.base.api_messages.api_links import APILink, APILinksMixin
from keylime.web.base.api_messages.api_meta import APIMeta, APIMetaMixin
from keylime.web.base.api_messages.api_error import APIError
from keylime.web.base.api_messages.api_info import APIInfo
from keylime.web.base.exceptions import InvalidMessage, MissingMember, UnexpectedMember, InvalidMember, StopAction
from keylime.models.base import BasicModel

logger = keylime_logging.init_logging("web")


class APIMessageBody(APILinksMixin, APIMetaMixin):
    @classmethod
    def load(cls, data):
        if not isinstance(data, Mapping):
            raise InvalidMember(f"cannot load object of type '{data.__class__.__name__}' as JSON:API document")

        data = data.copy()
        message_body = cls()

        if data.get("data"):
            message_body.load_resources(data.pop("data"))

        if data.get("errors"):
            message_body.load_errors(data.pop("errors"))

        if data.get("meta"):
            message_body.load_meta(data.pop("meta"))

        if data.get("links"):
            message_body.load_links(data.pop("links"))

        if data.get("jsonapi"):
            del data["jsonapi"]

        if data:
            raise UnexpectedMember(f"unexpected members given for a JSON:API message body: {list(data.keys())}")

        message_body.check_validity()

        return message_body

    @classmethod
    def from_record_errors(cls, records):
        return cls().add_record_errors(records)

    def __init__(self, *items):
        self._data = None
        self._errors = []
        self._meta = {}
        self._links = {}
        self._jsonapi = APIInfo()

        self.include(*items)
        
        # JSON:API features not currently implemented:
        #   - "included" member

    def add_resource(self, resource):
        if not isinstance(resource, base.APIResource):
            raise InvalidMember("resource added to JSON:API 'data' member must be an APIResource object")

        if self._errors:
            raise InvalidMember("resource cannot be added to JSON:API message body which contains an 'errors' member")

        if self._data is None:
            self._data = resource
            return

        if isinstance(self._data, base.APIResource):
            self._data = [self._data]

        if resource in self._data:
            raise InvalidMessage("resource already exists in JSON:API 'data' member")

        if any(res.id == resource.id and res.type == resource.type for res in self._data):
            raise InvalidMessage(
                f"resource with id '{resource.id}' and type '{resource.type}' already exists in JSON:API 'data' member"
            )

        self._data.append(resource)
        return self

    def load_resources(self, data):
        if not isinstance(data, (Mapping, Sequence)):
            raise InvalidMember("the JSON:API 'data' member must be a mapping or sequence")

        if isinstance(data, Mapping):
            data = [data]

        for item in data:
            resource = base.APIResource.load(item)
            self.add_resource(resource)

        return self

    def remove_resource(self, resource):
        if resource != self._data and resource not in self._data:
            raise KeyError("resource does not exist in JSON:API 'data' member")

        if isinstance(self._data, base.APIResource):
            self._data = None
        else:
            self._data.remove(resource)

            if not self._data:
                self._data = None
        
        return self

    def clear_resources(self):
        self._data = None
        return self

    def add_error(self, error):
        if not isinstance(error, APIError):
            raise TypeError(f"cannot add item of type '{error.__class__.__name__}' to JSON:API 'errors' member")

        if self._data:
            raise InvalidMember("error cannot be added to JSON:API message body which contains a 'data' member")

        if error in self._errors:
            raise KeyError(f"error already exists in JSON:API 'errors' member")

        self._errors.append(error)
        return self

    def load_errors(self, data):
        if not isinstance(data, Sequence):
            raise TypeError("object loaded as JSON:API 'errors' member must be a sequence") 

        for item in data:
            error = APIError.load(item)
            self.add_error(error)

        return self
    
    def add_record_errors(self, records):
        errors = {}
        single_resource = False

        if not isinstance(records, (list, tuple)):
            records = [records]
            single_resource = True

        for index, record in enumerate(records):
            if not isinstance(record, BasicModel):
                raise TypeError(
                    f"{type(self).__name__}.from_record_errors() called using record of type {type(record).__name__} "
                    f"which is not a subclass of BasicModel"
                )

            pointer_prefix = "/data/attributes/" if single_resource else f"/data/attributes/{index}/"
            errors.update(record.get_errors(pointer_prefix=pointer_prefix))

        for pointer, msgs in errors.items():
            pointer_parts = pointer.split("/")

            for msg in msgs:
                if single_resource:
                    msg = f"Attribute '{pointer_parts[3]}' {msg}."
                else:
                    msg = f"Attribute '{pointer_parts[3]}' in resource {pointer_parts[-1]} {msg}."

                self.add_error(APIError("invalid_resource_data").set_source(pointer=pointer).set_detail(msg))

        return self

    def remove_error(self, error):
        if error not in self._errors:
            raise KeyError(f"error does not exist in JSON:API 'errors' member")

        self._errors.remove(error)
        return self

    def clear_errors(self):
        self._errors.clear()
        return self

    def get_errors(self, code):
        return [ error for error in self.errors if error.api_code == code or error.http_code == code ]

    def include(self, *items):
        for item in items:
            if isinstance(item, base.APIResource):
                self.add_resource(item)
            elif isinstance(item, APIError):
                self.add_error(item)
            elif isinstance(item, APIMeta):
                self.add_meta(item)
            elif isinstance(item, APILink):
                self.add_link(item)
            else:
                raise TypeError(f"cannot add item of type '{item.__class__.__name__}' to JSON:API message body")

        return self

    def check_validity(self):
        if not self._data and not self._errors and not self._meta:
            raise MissingMember(
                "none of 'data', 'errors' or 'meta' is given for a JSON:API resource (at least one is required)"
            )

    def render(self):
        self.check_validity()

        output = {}

        if self.data:
            if isinstance(self.data, base.APIResource):
                output["data"] = self.data.render()
            else:
                output["data"] = [ item.render() for item in self.data ]

        if self.errors:
            output["errors"] = [ error.render() for error in self.errors ]

        if self.meta:
            output["meta"] = self.render_meta()

        if self.links:
            output["links"] = self.render_links()

        if self.jsonapi:
            output["jsonapi"] = self.jsonapi.render()

        return output

    def _get_current_path(self):
        current_location = self.links.get("self")

        if not current_location:
            return None

        return base.Route.make_abs_path(current_location.href)

    def _get_resource_path(self):
        resource_location = self.data.links.get("self") if isinstance(self.data, base.APIResource) else None

        if not resource_location:
            return None

        return base.Route.make_abs_path(resource_location.href, base_ref=self._get_current_path())

    def _is_resource_new(self):
        current_path = self._get_current_path()
        resource_path = self._get_resource_path()

        return bool(current_path and resource_path and self._get_current_path() != self._get_resource_path())

    def _infer_http_error_code(self):
        client_codes = set( error.http_code for error in self.client_errors )
        server_codes = set( error.http_code for error in self.server_errors )

        if len(client_codes) == 1 and len(server_codes) == 0:
            code = next(iter(client_codes))
        elif len(client_codes) == 0 and len(server_codes) == 1:
            code = next(iter(server_codes))
        elif len(client_codes) > 1 and len(server_codes) == 0:
            code = 400
        elif len(client_codes) == 0 and len(server_codes) > 1:
            code = 500
        elif len(client_codes) == 0 and len(server_codes) == 0:
            raise ValueError("cannot infer HTTP status code from APIMessageBody errors with blank http_code")
        else:
            raise ValueError("cannot infer HTTP status code from APIMessageBody with both 4xx and 5xx series errors")

        return code

    def _infer_http_code(self):
        if self.errors:
            return self._infer_http_error_code()
        
        return 201 if self._is_resource_new() else 200

    def _log_errors(self) -> None:
        if not self.errors:
            return

        logger.warning("Sending API response with error(s):")

        for error in self.errors:
            logger.warning("  • %s: %s", error.api_code, error.detail)

    def send_via(self, controller, *, code=None, status=None, stop_action=True):
        if not isinstance(controller, base.Controller):
            TypeError(
                f"APIMessageBody cannot be sent via object of type '{controller.__class__.__name__}' (expects instance "
                f"of Controller)"
            )

        if "self" not in self.links:
            self.include(APILink("self", controller.path))

        if self._is_resource_new():
            controller.set_header("Location", self._get_resource_path())

        if not code:
            code = self._infer_http_code()

        self._log_errors()
        controller.send_response(code, status, self.render(), "application/vnd.api+json")

        if stop_action:
            raise StopAction

    @property
    def data(self):
        if isinstance(self._data, list):
            return self._data.copy()
        else:
            return self._data

    @property
    def errors(self):
        return self._errors.copy()

    @property
    def client_errors(self):
        return [ error for error in self._errors if error.http_code >= 400 and error.http_code <= 499 ]

    @property
    def server_errors(self):
        return [ error for error in self._errors if error.http_code >= 500 and error.http_code <= 599 ]

    @property
    def meta(self):
        return MappingProxyType(self._meta)

    @property
    def links(self):
        return MappingProxyType(self._links)

    @property
    def jsonapi(self):
        return self._jsonapi