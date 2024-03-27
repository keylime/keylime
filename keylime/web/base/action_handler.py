from tornado.web import RequestHandler

from keylime.web.base.default_controller import DefaultController
from keylime.web.base.errors import ActionDispatchError, ActionIncompleteError


class ActionHandler(RequestHandler):
    """ActionHandler is a Tornado RequestHandler which accepts requests and directs them to the appropriate
    controller and action. It implements the callbacks which Tornado calls at the various points of the request
    lifecycle (see https://www.tornadoweb.org/en/stable/web.html#entry-points). When a new ActionHandler is
    instantiated, it receives a copy of the Server which it uses to find the highest-priority matching route and
    uses this to determine the controller to use and the action to call. If any part of this process fails,
    ActionHandler will gracefully handle the error condition and return an appropriate HTTP response.

    Similarly, if an exception is raised while executing an action, and that exception is not caught by the action
    itself, ActionHandler will safely handle this unexpected condition.

    ActionHandler instances are created by the Server as needed. You should not need to instantiate new ActionHandlers
    directly yourself.
    """

    def initialize(self, server):
        self._server = server
        self._matching_route = None
        self._controller = DefaultController(self)
        self._finished = False

    def prepare(self):
        # Find highest-priority route which matches the request
        route = self.server.first_matching_route(self.request.method, self.request.path)

        # Handle situations where a matching route does not exist
        if not route:
            # Check if any route with that path exists
            route_with_path = self.server.first_matching_route(None, self.request.path)

            if route_with_path:
                self.controller.method_not_allowed()
            else:
                self.controller.not_found()

            return

        # Handle situation where HTTP is used to access an HTTPS-only route
        if self.request.protocol == "http" and not route.allow_insecure:
            self.controller.https_required()

        # Save found route in object attribute
        self._matching_route = route
        # Create a new instance of the controller for the current ActionHandler instance
        self._controller = route.new_controller(self)

    def process_request(self):
        # Do not attempt to further process request if no route or controller is available
        if not self.matching_route or isinstance(self.controller, DefaultController):
            return

        # Parse any parameters in the query portion of the URL or in the body of the request
        try:
            query_params = self.controller.query_params
            form_params = self.controller.form_params
            json_params = self.controller.json_params
        except UnicodeError as err:
            # If a URL-encoded parameter (in the URL query string or the request body) includes any non-Unicode bytes,
            # treat this as a kind of "Bad Request"
            self.controller.send_response(400, "Malformed Request Parameter")
            return

        # Dynamically call appropriate action on the controller, passing along the parsed parameters
        try:
            self.matching_route.call_action(
                self.controller, self.request.path, {**query_params, **form_params, **json_params}
            )
        except ActionDispatchError as err:
            # If the union of path parameters, query parameters and form parameters do not match the method signature
            # of the action, respond with a "Bad Request" error
            self.controller.send_response(400, "Bad Request")
        except Exception as err:
            # Any other exception which is not caught within the action body should be treated as an unexpected error
            self.controller.send_response(500, "Internal Server Error")
            raise err

        # Handle situation in which no self.controller.send_response call is made by an action as an unexpected error
        if not self.finished:
            self.controller.send_response(500, "Internal Server Error")
            raise ActionIncompleteError(
                f"action '{self.matching_route.action}' in controller '{self.controller.__class__.__name__}'"
                f" did not produce a response"
            )

    def write_error(self, code, **kwargs):
        if code == 405 and kwargs.get("exc_info"):
            # If an HTTP method is not supported by the server (rather than not supported for a given resource),
            # Tornado incorrectly returns a 405 error but, according to RFC 9110, a 501 should be used instead
            self.controller.send_response(501, "Not Implemented")
        else:
            self.controller.send_response(code)

    def on_finish(self):
        self._finished = True

    def get(self):
        self.process_request()

    def head(self):
        self.process_request()

    def post(self):
        self.process_request()

    def put(self):
        self.process_request()

    def patch(self):
        self.process_request()

    def delete(self):
        self.process_request()

    def options(self):
        self.process_request()

    @property
    def server(self):
        return self._server

    @property
    def matching_route(self):
        return self._matching_route

    @property
    def controller(self):
        return self._controller

    @property
    def finished(self):
        return self._finished
