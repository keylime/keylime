import http.client
import json
import re
from types import MappingProxyType
from typing import Union

from tornado.escape import parse_qs_bytes
from tornado.httputil import parse_body_arguments


class Controller:
    """A controller represents a collection of actions that an API consumer can perform on a resource or set of
    resources. Each action translates a request into method calls made to a model (or multiple models). These calls
    include those needed to query the database and locate the relevant records and also those needed to render these
    records to a representation which can be returned to the API consumer.

    Example
    -------

    A controller is any class which inherits from the ``Controller`` class as follows:

        class AgentsController(Controller):
            def index(self, **params):
                results = Agent.all()
                self.respond(200, "Success", results)

    The instance methods defined by a controller are referred to as the controller's "actions". These should typically
    be referenced by a route defined by a ``Server`` subclass.

    Each action handles a specify type of request and receives a number of parameters which are extracted from the
    incoming request. These parameters include those present in the URL or in the HTTP request body. Parameters will be
    extracted so long as they are encoded in URL query format, as form data or as JSON. Additionally, the parameters
    will include any indicated by the route's pattern (refer to the documentation for ``Route`` for details).

    All actions should accept any arbitrary keyword argument but may define additional named parameters. Typically, the
    method signature of an action will include all parameters that the action expects to be included in requests made by
    the API consumer::

        def show(self, id, format=None, **params):
            # (Implementation...)

    In the ``show`` action above, the ``id`` parameter is required and used to locate the record. The result returned
    will depend on ``format`` which is optional and defaults to ``None``.

    If a required parameter is missing from an incoming request, this will be handled by ``ActionHandler`` which will
    respond with a 400 "Bad Request" error.

    Controller vs. Model
    --------------------

    When deciding whether business logic should be implemented as part of a controller or the model itself, the
    general rule is that the controller should only contain the minimum code needed to receive data from the request
    and prepare it to be received in the expected format by methods defined by the model. These should include methods
    for locating records in the database (these are typically those inherited from the ``PersistableModel`` class) as
    well as methods for creating new records, modifying existing records and displaying records (these are all
    typically defined by each individual model).
    """

    # Regex used to extract the API version from a URL, irrespective of how routes are defined
    VERSION_REGEX = re.compile("^\\/v(\\d+)(?:\\.(\\d+))*")

    @staticmethod
    def decode_url_query(query: bytes) -> dict[str, str | list[str]]:
        """Parses a binary query string (whether from a URL or HTTP body) into a dict of Unicode strings. If multiple
        instance of the same key are present in the string, their values are collected into a list.

        Note that keys and values are interpreted according to the latin-1 unicode character block because of how
        Tornado has implemented query string parsing. This is a valid interpretation of RFC 3986 because the standard
        does not specify how query strings should be interpreted. The benefit is that all possible bytes can be
        represented as a character, but has the drawback that non-latin characters represented in the query string
        using URI percent-encoding will be converted to the wrong characters.
        """
        query_params = parse_qs_bytes(query)

        for name, values in query_params.items():
            try:
                if len(values) > 1:
                    query_params[name] = (bytes.decode(val) for val in values)
                else:
                    query_params[name] = bytes.decode(values[0])

            except UnicodeError:
                raise

        return query_params

    @staticmethod
    def decode_multipart_form(content_type: str, form: bytes) -> dict[str, Union[str, bytes, list[str | bytes]]]:
        """Parses a binary HTTP body encoded with the "multipart/form-data" media type into a dict of Unicode strings.
        Multiple instances of the same key are collected into a list.

        As a multipart/form-data body may contain arbitrary binary data, values not interpretable as Unicode will be
        left as-is and returned as bytes object. Ideally, the media type of each part would be used to determine its
        encoding, but Tornado's implementation does not make use of this feature of RFC 7578.
        """
        form_params = {}

        parse_body_arguments(content_type, form, form_params, {})

        for name, values in form_params.items():
            try:
                if len(values) > 1:
                    form_params[name] = (bytes.decode(val) for val in values)
                else:
                    form_params[name] = bytes.decode(values[0])

            except UnicodeError:
                form_params[name] = values

        return form_params

    @staticmethod
    def prepare_http_body(body, content_type=None):
        """Prepares an object to be included in the body of an HTTP request or response and infers the appropriate
        media type unless provided. `body` will be serialised into JSON if it contains a `dict` or `list` which is
        serialisable unless a `content_type` other than `"application/json"` is provided.

        :param body: The body of the request/response
        :param content_type: An optional media/MIME type used to interpret the contents of `body`

        :returns: `(body, content_type)` where `body` is the value the caller should use as the body of the HTTP
        request/response and `content_type` is the that the caller should include in the "Content-Type" HTTP header.
        """
        if content_type and not isinstance(content_type, str):
            raise TypeError(f"content_type '{content_type}' is not of type str")

        if content_type:
            content_type = content_type.lower().strip()

        match (body, content_type):
            case (None, _):
                body = None
                content_type = content_type
            case ("", _):
                body = ""
                content_type = "text/plain"
            case (_, "text/plain"):
                body = str(body)
                content_type = "text/plain"
            case (_, "application/json") if isinstance(body, str):
                body = body
                content_type = "application/json"
            case (_, "application/json"):
                body = json.dumps(body).encode("utf-8")
                content_type = "application/json"
            case (_, None) if isinstance(body, str):
                body = body
                content_type = "text/plain"
            case (_, None) if isinstance(body, dict) or isinstance(body, list):
                try:
                    body = json.dumps(body).encode("utf-8")
                    content_type = "application/json"
                except TypeError:
                    body = None
                    content_type = None
            case (_, _):
                body = body
                content_type = content_type

        return (body, content_type)

    @staticmethod
    def __new__(cls, action_handler, *args, **kwargs):
        if cls is Controller:
            raise TypeError("Only children of the Controller class may be instantiated")
        return super(Controller, cls).__new__(cls, *args, **kwargs)

    def __init__(self, action_handler):
        self._action_handler = action_handler
        self._path_params = None
        self._query_params = None
        self._form_params = None
        self._json_params = None
        self._major_version = None
        self._minor_version = None

    def send_response(self, status_code=200, status_msg=None, body=None, content_type=None):
        """Sends a response over the active HTTP connection. The caller can choose which parameters to provide and
        the others will be inferred. `body` is typically expected to be a `dict` or a `list` which is convertible to
        JSON, or otherwise a string which will be treated as plain text. This behaviour can be overriden by specifying
        a `content_type` other than `"application/json"`.

        :param status_code: An optional integer representing an HTTP status code (defaults to ``200``)
        :param status_msg: An optional string to be used as the status message (inferred from ``code`` by default)
        :param body: An optional string or JSON-convertible value to use as the response body
        :param content_type: An optional string to use as the MIME type of ``body`` (inferred from ``body`` by default)

        :raises: :class:`TypeError`: A given argument is of an incorrect type
        """

        if not isinstance(status_code, int):
            raise TypeError(f"status code '{status_code}' is not of type int")

        if status_msg and not isinstance(status_msg, str):
            raise TypeError(f"status message '{status_msg}' is not of type str")

        if content_type and not isinstance(content_type, str):
            raise TypeError(f"content_type '{content_type}' is not of type str")

        if not status_msg:
            status_msg = http.client.responses[status_code]

        self.action_handler.set_status(status_code)
        body, content_type = Controller.prepare_http_body(body, content_type)

        if content_type:
            self.action_handler.set_header("Content-Type", "application/json")

        if body:
            self.action_handler.write(body)

        self.action_handler.finish()

    def respond(self, code=200, status=None, data=None):
        """Converts a Python data structure to JSON and wraps it in the following boilerplate JSON object which is
        returned by all v2 endpoints:

        {
            "code": code
            "status": status
            "data": data
        }

        The HTTP status message is inferred from ``code`` and is different from ``status``.

        :param code: An optional integer to use as HTTP status code and include in the JSON response
        :param status: An optional string to include in the JSON response as a status message
        :param data: An optional JSON-convertible value to include in the JSON response as return data

        :raises: :class:`TypeError`: A given argument is of an incorrect type
        """
        if not status:
            status = http.client.responses[code]

        if not data:
            data = {}

        response = {"code": code, "status": status, "results": data}

        self.send_response(status_code=code, body=response)

    @property
    def action_handler(self):
        return self._action_handler

    @property
    def request_body(self):
        return self.action_handler.request.body

    @property
    def path(self):
        return self.action_handler.request.path

    @property
    def path_params(self):
        if not self._path_params:
            path_params = self.action_handler.matching_route.capture_params(self.path)

            # Note: At this point, the parameters defined by the route will have previously been extracted from the
            # path in order to route the request to the controller + action, so if capture_params raises an exception
            # here, this would be an unexpected error which should be processed by the default handler.

            # Protect the params dictionary from editing with MappingProxyType before saving in the object and returning
            self._path_params = MappingProxyType(path_params)

        return self._path_params

    @property
    def query_params(self):
        if not self._query_params:
            try:
                query_params = Controller.decode_url_query(self.action_handler.request.query)
            except UnicodeError:
                raise

            self._query_params = MappingProxyType(query_params)

        return self._query_params

    @property
    def form_params(self):
        if not self._form_params:
            content_type = self.action_handler.request.headers.get("Content-Type")
            form_params = {}

            if content_type and content_type.startswith("application/x-www-form-urlencoded"):
                try:
                    form_params = Controller.decode_url_query(self.request_body)
                except UnicodeError:
                    raise

                # As with query parameters, an x-www-form-urlencoded body is assumed to only encode unicode text.

            if content_type and content_type.startswith("multipart/form-data"):
                form_params = Controller.decode_multipart_form(content_type, self.request_body)

            # If the request's Content-Type is neither application/x-www-form-urlencoded nor multipart/form-data,
            # form_params is left blank.

            self._form_params = MappingProxyType(form_params)

        return self._form_params

    @property
    def json_params(self):
        if not self._form_params:
            content_type = self.action_handler.request.headers.get("Content-Type")
            json_params = {}

            if content_type and content_type.startswith("application/json"):
                try:
                    json_content = json.loads(self.request_body)
                except json.JSONDecodeError:
                    raise

                if isinstance(json_content, dict):
                    json_params = json_content

            # If the request's Content-Type is not application/json nor multipart/form-data, json_params is left blank.

            self._json_params = MappingProxyType(json_params)

        return self._json_params

    @property
    def major_version(self) -> int | None:
        """Extracts the major API version from the path, if present. E.g., if the path being handled starts with
        "/v2.0", "/v2.5" or "/v2", this method will return ``2``.
        """
        if not self._major_version:
            result = Controller.VERSION_REGEX.match(self.path)

            try:
                major_version = int(result.group(1)) if result else None
            except (TypeError, ValueError):
                major_version = None

            self._major_version = major_version

        return self._major_version

    @property
    def minor_version(self) -> int | None:
        """Extracts the minor API version from the path, if present. E.g., if the path being handled starts with
        "/v2.0", this method will return ``0``. If the path starts with "/v2" instead, the method will return ``None``.
        """
        if not self._major_version:
            result = Controller.VERSION_REGEX.match(self.path)

            try:
                minor_version = int(result.group(2)) if result else None
            except (TypeError, ValueError):
                minor_version = None

            self._minor_version = minor_version

        return self._minor_version
