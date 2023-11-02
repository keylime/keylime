import re
from inspect import iscoroutinefunction
from typing import Any, Mapping, Optional

from keylime.web.base.controller import Controller
from keylime.web.base.errors import (
    ActionDispatchError,
    ActionUndefined,
    InvalidMethod,
    InvalidPathOrPattern,
    PatternMismatch,
)


class Route:
    """A route represents a single unit of routing logic by which a set of similar incoming requests can all be directed
    to a specific action on a controller to apply specific processing logic unique to that set of requests.

    Requests are matched against the HTTP method and URI path pattern defined by the route. Matching requests are then
    directed to be handled by a specific controller and action.

    This class implements template-based routing and, in the process, codifies the syntax of path patterns, provides
    parsing logic to check if a particular path matches the route's pattern, and extracts parameters from the path as
    defined by the pattern. It also makes the defined controller and action retrievable as a callable function to be
    invoked at the appropriate time by ``ActionHandler``.

    Example
    -------

    Typically, a route is created by calling a helper method in the ``Server`` abstract class from the special
    ``_routes`` method. For example::

        class ExampleServer(Server):
            def _routes(self):
                self._get("/v:version/agents/:id", AgentsController, "show")

    This will create a new route which will match any incoming GET request with a path that matches the pattern given
    as the first parameter to the ``get`` method. Matching requests will be handled by the ``show`` instance method
    defined in the ``AgentsController`` class. The  ``AgentsController`` class must inherit from ``Controller``.

    Helpers for the other HTTP methods also exist. The full list is as follows: ``_get``, ``_head``, ``_post``,
    ``_put``, ``_patch``, ``_delete`` and ``_options``.

    Routes are not usually created by using the ``Routes`` class directly, except in the ``Server`` abstract
    class itself.

    Patterns
    --------

    The above pattern ``"/v:version/agents/:id"`` will match on incoming requests for any of the following resources,
    for example:

    - ``"/v3.0/agents/123"``
    - ``"/v3.0/agents/123/"``
    - ``"/v2.1/agents/4567"``
    - ``"/vinvalidversion/agents/invalidid"``

    The defined action will need to handle all these cases, including any invalid paths.

    The pattern will not match on incoming requests for these resources:

    - ``"/v3.0/agents/"``
    - ``"/v3.0/agents/123/nonce"``
    - ``"/3.0/agents/123"``

    If a request's path matches against the pattern, the ``"version"`` and ``id`` parameters are extracted from the path
    and provided as arguments when calling the action. For example, in the ``"/v3.0/agents/123"`` case, the action
    will receive ``"3.0"`` and ``"123"`` as arguments.
    """

    # A subset of HTTP methods defined in RFC 9110 and RFC 5789 which will be commonly handled by a REST API
    ALLOWABLE_METHODS = ["get", "head", "post", "put", "patch", "delete", "options"]

    # The ABNF defined in RFC 3986 (Appendix A) for the absolute path component of a URI is as follows:
    # path-absolute = "/" [ segment-nz *( "/" segment ) ]
    # segment       = *pchar
    # segment-nz    = 1*pchar
    # pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
    # unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
    # pct-encoded   = "%" HEXDIG HEXDIG
    # sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="

    # This ABNF translates to the following regular expression syntax:
    UNRESERVED = "[A-Za-z0-9-._~]"
    PCT_ENCODED = "%[0-9A-Fa-f]{2}"
    SUB_DELIMS = "[!$&'()*+,;=]"
    PCHAR = f"{UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|[:@]"
    SEGMENT = f"(?:{PCHAR})*"
    SEGMENT_NZ = f"(?:{PCHAR})+"
    PATH_ABSOLUTE = f"\\/(?:{SEGMENT_NZ}(?:\\/{SEGMENT})*){{0,1}}"
    PATH_ABSOLUTE_REGEX = re.compile(f"^{PATH_ABSOLUTE}$")

    @staticmethod
    def validate_abs_path(path: str) -> bool:
        """Validates the path component of a URI according to RFC 3986.

        :param path: The absolute path (starting with a "/") to validate

        :returns: ``True`` if the path conforms to the correct syntax, ``False`` otherwise
        """
        return bool(Route.PATH_ABSOLUTE_REGEX.match(path))

    @staticmethod
    def split_path(path: str) -> list[str]:
        """Splits a URI path into segments by slash. Assumes the value provided is a valid path.

        :param path: The path to split into segments

        :returns: A list of path segment strings
        """
        segments = path.split("/")

        # If the path starts with a slash, the first segment will be an empty string, so remove
        if not segments[0]:
            del segments[0]

        # If the path ends with a slash, the final segment will be an empty string, so remove
        if not segments[-1]:
            del segments[-1]

        return segments

    def __init__(
        self, method: str, pattern: str, controller: type[Controller], action: str, allow_insecure: bool = False
    ) -> None:
        """Instantiates a newly created route with the given method, pattern, controller and action. Typically, this
        should be done by using the helper methods in the ``Server`` abstract base class.

        :param method: The HTTP method which the route will match (e.g., ``"get"``, ``"post"``, etc.)
        :param pattern: The pattern which the route will match against a given path
        :param controller: A class which inherits from ``Controller`` and contains the actions for this route
        :param action: The name of an instance method in the controller which will be called on a matching request
        :param allow_insecure: Whether this route should accept requests made over insecure HTTP (default: ``False``)

        :raises: :class:`TypeError`: An argument is of an incorrect type
        :raises: :class:`InvalidMethod`: The given HTTP method is not one accepted by the Routes class
        :raises: :class:`InvalidPathOrPattern`: he pattern given does not conform to the expected syntax
        :raises: :class:`ActionUndefined`: The action given is not a method which has been defined in the controller
        """
        if not isinstance(method, str):
            raise TypeError("route method must be of type str")

        if not isinstance(pattern, str):
            raise TypeError("route pattern must be of type str")

        if not issubclass(controller, Controller):
            raise TypeError("route controller must be a subclass of Controller")

        if not isinstance(action, str):
            raise TypeError("route action must be of type str")

        method = method.lower()

        if method not in Route.ALLOWABLE_METHODS:
            raise InvalidMethod(f"route defined with invalid method '{method}'")

        if not Route.validate_abs_path(pattern):
            raise InvalidPathOrPattern(f"route defined with pattern '{pattern}' which is not a valid URI path")

        if not hasattr(controller, action) or not callable(getattr(controller, action)):
            raise ActionUndefined(
                f"route defined with action '{action}' which does not exist in controller '{controller.__name__}'"
            )

        self._method = method
        self._pattern = pattern
        self._controller = controller
        self._action = action
        self._allow_insecure = bool(allow_insecure)

        self._parse_pattern()

    def __repr__(self) -> str:
        """Returns a code-like string representation of the route

        :returns: string
        """
        return f"Route({self.method}, {self.pattern}, {self.controller.__name__}, {self.action})"

    def _parse_pattern(self) -> None:
        """Parses the route's pattern into (1) parts which are expected to appear verbatim in matching paths and (2)
        parameters which can be substituted for any URI-valid string (except a slash) in matching paths.

        A pattern of ``"/v:version/agents/:id"`` would be parsed into the following data structure, saved in
        ``self._parsed_pattern``::

            [
                {"prefix": "v", "param": "version"},
                "agents",
                {"prefix": "", "param": "id"}
            ]

        :raises: :class:`InvalidPathOrPattern`: The route's pattern is invalid
        """
        # pylint: disable=no-else-raise

        pattern_segments = Route.split_path(self.pattern)
        parsed_pattern: list[str | dict[str, str]] = []

        for segment in pattern_segments:
            delimiter_count = segment.count(":")

            if delimiter_count >= 2:
                # Multiple parameters in a single segment (e.g., "/:one:two") would be ambiguous, so this is not allowed
                raise InvalidPathOrPattern(f"pattern '{self.pattern}' contains multiple parameters in a single segment")
            elif delimiter_count == 1:
                # If the segment has exactly one parameter, parse the segment into its component parts: the parameter
                # plus anything that precedes the parameter
                parts = segment.split(":")
                prefix = parts[0]
                param_name = parts[1]

                # A parameter delimiter must be followed by a name (e.g., "/:/example" is not allowed)
                if len(param_name) <= 0:
                    raise InvalidPathOrPattern(f"pattern '{self.pattern}' contains a parameter with no name")

                parsed_pattern.append({"prefix": prefix, "param": param_name})
            else:
                # If the segment has no parameters, leave it as is
                parsed_pattern.append(segment)

        self._parsed_pattern = parsed_pattern

    def capture_params(self, path: str) -> Mapping[str, str]:
        """Extract parameters from a URI path according to the route pattern.

        :param pattern: The path to process against the route pattern

        :raises: :class:`InvalidPathOrPattern`: The given path is invalid
        :raises: :class:`PatternMismatch`: The given path does not match the route's pattern

        :returns: A dictionary of parameter names and values
        """
        # pylint: disable=consider-using-enumerate, no-else-continue

        if not Route.validate_abs_path(path):
            raise InvalidPathOrPattern(f"path '{path}' is not a valid URI")

        parameters = {}
        path_segments = Route.split_path(path)

        if len(self._parsed_pattern) != len(path_segments):
            raise PatternMismatch(
                f"path '{path}' does not contain the same number of slash-separated segments as "
                f"route pattern '{self.pattern}'"
            )

        for i in range(len(self._parsed_pattern)):
            # If this segment of the parsed pattern is a string, it does not contain any parameters,
            # so it should match the corresponding segment of the path verbatim
            if isinstance(self._parsed_pattern[i], str):
                if self._parsed_pattern[i] == path_segments[i]:
                    continue
                else:
                    raise PatternMismatch(
                        f"segment '{path_segments[i]}' of path '{path}' does not match '{self._parsed_pattern[i]}' "
                        f"from route pattern '{self.pattern}'"
                    )

            prefix = self._parsed_pattern[i]["prefix"]  # type: ignore
            param_name = self._parsed_pattern[i]["param"]  # type: ignore

            # If this segment of the parsed pattern contains a substring before the parameter, this
            # substring prefix should match the corresponding substring in the pattern verbatim
            if path_segments[i][0 : len(prefix)] != prefix:
                raise PatternMismatch(
                    f"prefix '{prefix}' not found in segment '{path_segments[i]}' of path '{path}' as required "
                    f"by route pattern '{self.pattern}'"
                )

            param_value = path_segments[i][len(prefix) :]

            # A parameter should capture at least one character in order for the pattern to be considered matching
            if len(param_value) <= 0:
                raise PatternMismatch(
                    f"segment '{path_segments[i]}' of path '{path}' does not contain a value matching "
                    f"parameter ':{param_name}' from route pattern '{self.pattern}'"
                )

            parameters[param_name] = param_value

        return parameters

    def matches_path(self, path: str) -> bool:
        """Checks whether a given path conforms to the route pattern.

        :param path: The path to check against the route pattern

        :raises: :class:`InvalidPathOrPattern`: The given path is invalid

        :returns: ``True`` if the path matches the route pattern, ``False`` otherwise
        """
        try:
            self.capture_params(path)
        except PatternMismatch:
            return False

        return True

    def matches(self, method: str, path: str) -> bool:
        """Checks whether a given method and path conforms to the route method and pattern.

        :param method: The HTTP method to check against the route method
        :param path: The path to check against the route pattern

        :raises: :class:`InvalidMethod`: The given method is invalid
        :raises: :class:`InvalidPathOrPattern`: The given path is invalid

        :returns: ``True`` if the method and path both match the route, ``False`` otherwise
        """
        method = method.lower()

        if method not in Route.ALLOWABLE_METHODS:
            raise InvalidMethod(f"method '{method}' is not an allowable HTTP method")

        return self.method == method and self.matches_path(path)

    def new_controller(self, *args: Any, **kargs: Any) -> Controller:
        """Creates a new instance of the controller specified by the route in order to handle a new incoming request.

        :param *args: The positional arguments to pass to the controller's constructor, if any
        :param **kargs: The keyword arguments to pass to the controller's constructor, if any

        :returns: A new controller instance
        """
        return self.controller(*args, **kargs)

    async def call_action(self, controller_inst: Controller, params: Optional[Mapping[str, Any]] = None) -> Any:
        """Calls the controller action specified by the route in order to handle a new incoming request.

        Any exceptions which occur in the body of the action's method definition will not be caught by this method and
        need to be handled by the caller.

        :param controller_inst: The controller instance to use to handle the request
        :param params: A optional list of request parameters to use instead of discovering them from controller_inst

        :raises: :class:`ParamDecodeError`: The request parameters are malformed and cannot be parsed

        :raises: :class:`ActionDispatchError`: The request parameters do not match those defined in the method
        signature for the action

        :raises: :class:`Exception`: An uncaught exception occurred within the body of the action

        :returns: The result returned by the action
        """
        # pylint: disable=no-else-return, no-else-raise

        if not isinstance(controller_inst, self.controller):
            raise TypeError(
                f"the given controller object '{controller_inst.__class__.__name__}' is not an instance of the route's "
                f"controller class {self.controller.__name__}"
            )

        if params is None:
            params = controller_inst.get_params()

        action_func = getattr(controller_inst, self.action)

        try:
            if iscoroutinefunction(action_func):
                return await action_func(**params)
            else:
                return action_func(**params)

        except TypeError as err:
            # If there is an error calling the action (e.g., too few arguments are provided), catch this and raise it
            # as an ActionDispatchError. Otherwise, the error has occurred somewhere within the action itself and should
            # be handled separately as an unexpected condition.
            if err.__traceback__ and err.__traceback__.tb_next is None:
                raise ActionDispatchError(str(err)) from None
            else:
                raise err

    @property
    def method(self) -> str:
        return self._method

    @property
    def pattern(self) -> str:
        return self._pattern

    @property
    def controller(self) -> type[Controller]:
        return self._controller

    @property
    def action(self) -> str:
        return self._action

    @property
    def allow_insecure(self) -> bool:
        return self._allow_insecure
