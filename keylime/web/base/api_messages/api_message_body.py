from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from keylime import keylime_logging
from keylime.models.base import BasicModel
from keylime.web import base
from keylime.web.base.api_messages.api_error import APIError
from keylime.web.base.api_messages.api_info import APIInfo
from keylime.web.base.api_messages.api_links import APILink, APILinksMixin
from keylime.web.base.api_messages.api_meta import APIMeta, APIMetaMixin
from keylime.web.base.exceptions import InvalidMember, InvalidMessage, MissingMember, StopAction, UnexpectedMember

if TYPE_CHECKING:
    from keylime.web.base.controller import Controller

logger = keylime_logging.init_logging("web")


class APIMessageBody(APILinksMixin, APIMetaMixin):
    @classmethod
    def load(cls, data: Mapping[str, Any]) -> "APIMessageBody":
        if not isinstance(data, Mapping):
            raise InvalidMember(f"cannot load object of type '{data.__class__.__name__}' as JSON:API document")

        data_dict = dict(data)  # type: ignore[assignment, attr-defined]
        message_body = cls()

        if data_dict.get("data"):
            message_body.load_resources(data_dict.pop("data"))

        if data_dict.get("errors"):
            message_body.load_errors(data_dict.pop("errors"))

        if data_dict.get("meta"):
            message_body.load_meta(data_dict.pop("meta"))

        if data_dict.get("links"):
            message_body.load_links(data_dict.pop("links"))

        if data_dict.get("jsonapi"):
            del data_dict["jsonapi"]

        if data_dict:
            raise UnexpectedMember(f"unexpected members given for a JSON:API message body: {list(data_dict.keys())}")

        message_body.check_validity()

        return message_body

    @classmethod
    def from_record_errors(cls, records: BasicModel | Sequence[BasicModel]) -> "APIMessageBody":
        return cls().add_record_errors(records)

    def __init__(self, *items: base.APIResource | APIError | APIMeta | APILink):
        self._data: base.APIResource | list[base.APIResource] | None = None
        self._errors: list[APIError] = []
        self._meta: dict[str, APIMeta] = {}
        self._links: dict[str, APILink] = {}
        self._jsonapi: APIInfo = APIInfo()

        self.include(*items)

        # JSON:API features not currently implemented:
        #   - "included" member

    def add_resource(self, resource: base.APIResource) -> "APIMessageBody":
        if not isinstance(resource, base.APIResource):
            raise InvalidMember("resource added to JSON:API 'data' member must be an APIResource object")

        if self._errors:
            raise InvalidMember("resource cannot be added to JSON:API message body which contains an 'errors' member")

        if self._data is None:
            self._data = resource
            return self

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

    def load_resources(self, data: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> "APIMessageBody":
        if not isinstance(data, (Mapping, Sequence)):
            raise InvalidMember("the JSON:API 'data' member must be a mapping or sequence")

        data_list: Sequence[Mapping[str, Any]]
        if isinstance(data, Mapping):
            data_list = [data]
        else:
            data_list = data

        for item in data_list:
            resource = base.APIResource.load(item)
            self.add_resource(resource)

        return self

    def remove_resource(self, resource: base.APIResource) -> "APIMessageBody":
        if resource != self._data and (not isinstance(self._data, list) or resource not in self._data):
            raise KeyError("resource does not exist in JSON:API 'data' member")

        if isinstance(self._data, base.APIResource):
            self._data = None
        else:
            self._data.remove(resource)  # type: ignore[union-attr]

            if not self._data:
                self._data = None

        return self

    def clear_resources(self) -> "APIMessageBody":
        self._data = None
        return self

    def add_error(self, error: APIError) -> "APIMessageBody":
        if not isinstance(error, APIError):
            raise TypeError(f"cannot add item of type '{error.__class__.__name__}' to JSON:API 'errors' member")

        if self._data:
            raise InvalidMember("error cannot be added to JSON:API message body which contains a 'data' member")

        if error in self._errors:
            raise KeyError("error already exists in JSON:API 'errors' member")

        self._errors.append(error)
        return self

    def load_errors(self, data: Sequence[Mapping[str, Any]]) -> "APIMessageBody":
        if not isinstance(data, Sequence):
            raise TypeError("object loaded as JSON:API 'errors' member must be a sequence")

        for item in data:
            error = APIError.load(item)  # type: ignore[attr-defined]  # pylint: disable=no-member
            self.add_error(error)

        return self

    def add_record_errors(self, records: BasicModel | Sequence[BasicModel]) -> "APIMessageBody":
        errors: dict[str, list[str]] = {}
        single_resource = False

        records_list: Sequence[BasicModel]
        if not isinstance(records, (list, tuple)):
            records_list = [records]  # type: ignore[list-item]
            single_resource = True
        else:
            records_list = records

        for index, record in enumerate(records_list):
            if not isinstance(record, BasicModel):
                raise TypeError(
                    f"{type(self).__name__}.from_record_errors() called using record of type {type(record).__name__} "
                    f"which is not a subclass of BasicModel"
                )

            pointer_prefix = "/data/attributes/" if single_resource else f"/data/attributes/{index}/"
            errors.update(record.get_errors(pointer_prefix=pointer_prefix))  # type: ignore[no-untyped-call]

        for pointer, msgs in errors.items():
            pointer_parts = pointer.split("/")

            for msg in msgs:
                if single_resource:
                    msg = f"Attribute '{pointer_parts[3]}' {msg}."
                else:
                    msg = f"Attribute '{pointer_parts[3]}' in resource {pointer_parts[-1]} {msg}."

                self.add_error(APIError("invalid_resource_data").set_source(pointer=pointer).set_detail(msg))

        return self

    def remove_error(self, error: APIError) -> "APIMessageBody":
        if error not in self._errors:
            raise KeyError("error does not exist in JSON:API 'errors' member")

        self._errors.remove(error)
        return self

    def clear_errors(self) -> "APIMessageBody":
        self._errors.clear()
        return self

    def get_errors(self, code: str | int) -> list[APIError]:
        return [error for error in self.errors if code in (error.api_code, error.http_code)]

    def include(self, *items: base.APIResource | APIError | APIMeta | APILink) -> "APIMessageBody":
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

    def check_validity(self) -> None:
        if not self._data and not self._errors and not self._meta:
            raise MissingMember(
                "none of 'data', 'errors' or 'meta' is given for a JSON:API resource (at least one is required)"
            )

    def render(self) -> dict[str, Any]:
        self.check_validity()

        output: dict[str, Any] = {}

        if self.data:
            if isinstance(self.data, base.APIResource):
                output["data"] = self.data.render()
            else:
                output["data"] = [item.render() for item in self.data]

        if self.errors:
            output["errors"] = [error.render() for error in self.errors]

        if self.meta:
            output["meta"] = self.render_meta()

        if self.links:
            output["links"] = self.render_links()

        if self.jsonapi:
            output["jsonapi"] = self.jsonapi.render()

        return output

    def _get_current_path(self) -> str | None:
        current_location = self.links.get("self")

        if not current_location:
            return None

        return base.Route.make_abs_path(current_location.href)  # type: ignore[no-any-return, arg-type]

    def _get_resource_path(self) -> str | None:
        resource_location = self.data.links.get("self") if isinstance(self.data, base.APIResource) else None

        if not resource_location:
            return None

        current_path = self._get_current_path()
        if current_path:
            return base.Route.make_abs_path(resource_location.href, base_ref=current_path)  # type: ignore[no-any-return, arg-type]
        return base.Route.make_abs_path(resource_location.href)  # type: ignore[no-any-return, arg-type]

    def _is_resource_new(self) -> bool:
        current_path = self._get_current_path()
        resource_path = self._get_resource_path()

        return bool(current_path and resource_path and self._get_current_path() != self._get_resource_path())

    def _infer_http_error_code(self) -> int:
        client_codes = set(error.http_code for error in self.client_errors)
        server_codes = set(error.http_code for error in self.server_errors)

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

        return code  # type: ignore[return-value]

    def _infer_http_code(self) -> int:
        if self.errors:
            return self._infer_http_error_code()

        return 201 if self._is_resource_new() else 200

    def _log_errors(self) -> None:
        if not self.errors:
            return

        logger.warning("Sending API response with error(s):")

        for error in self.errors:
            logger.warning("  • %s: %s", error.api_code, error.detail)

    def send_via(
        self, controller: "Controller", *, code: int | None = None, status: str | None = None, stop_action: bool = True
    ) -> None:
        if not isinstance(controller, base.Controller):
            raise TypeError(
                f"APIMessageBody cannot be sent via object of type '{controller.__class__.__name__}' (expects instance "
                f"of Controller)"
            )

        if "self" not in self.links:
            self.include(APILink("self", controller.path))

        if self._is_resource_new():
            resource_path = self._get_resource_path()
            if resource_path:
                controller.set_header("Location", resource_path)

        if not code:
            code = self._infer_http_code()

        self._log_errors()
        controller.send_response(code, status, self.render(), "application/vnd.api+json")

        if stop_action:
            raise StopAction

    @property
    def data(self) -> base.APIResource | list[base.APIResource] | None:
        if isinstance(self._data, list):
            return self._data.copy()
        return self._data

    @property
    def errors(self) -> list[APIError]:
        return self._errors.copy()

    @property
    def client_errors(self) -> list[APIError]:
        return [
            error for error in self._errors if error.http_code and error.http_code >= 400 and error.http_code <= 499
        ]

    @property
    def server_errors(self) -> list[APIError]:
        return [
            error for error in self._errors if error.http_code and error.http_code >= 500 and error.http_code <= 599
        ]

    @property
    def meta(self) -> MappingProxyType[str, APIMeta]:
        return MappingProxyType(self._meta)

    @property
    def links(self) -> MappingProxyType[str, APILink]:
        return MappingProxyType(self._links)

    @property
    def jsonapi(self) -> APIInfo:
        return self._jsonapi
