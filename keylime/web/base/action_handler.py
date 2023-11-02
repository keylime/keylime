import re
import time
import traceback
from inspect import iscoroutinefunction
from typing import TYPE_CHECKING, Any, Mapping, Optional

from tornado.web import RequestHandler

from keylime import keylime_logging
from keylime.web.base.default_controller import DefaultController
from keylime.web.base.errors import ActionDispatchError, ActionIncompleteError, ActionUndefined, ParamDecodeError

if TYPE_CHECKING:
    from keylime.web.base.controller import Controller
    from keylime.web.base.route import Route
    from keylime.web.base.server import Server

logger = keylime_logging.init_logging("web")


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

    # Because RequestHandler.data_received raises a NotImplemented error, Pylint thinks this is an abstract method
    # despite not being declared as such (see https://stackoverflow.com/questions/31939132/)
    # pylint: disable=abstract-method

    def _log_action(self, controller: "Controller", action: str) -> None:
        self._action_call_stack.append((controller, action))
        controller_cls = controller.__class__

        logger.debug("Invoking action '%s' from %s in %s", action, controller_cls.__name__, controller_cls.__module__)

    def _log_exception(self, err: Exception) -> None:
        logger.error("An uncaught exception occurred while handling a request:")

        # Take the list of strings returned by format_exception, where each string ends in a newline and may contain
        # internal newlines, and split the concatenation of all the strings by newline
        message = "".join(traceback.format_exception(err))
        lines = message.split("\n")

        for line in lines:
            if line.strip() != "":
                logger.error(line)

    async def _invoke_route_action(
        self,
        action: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
        ignore_param_errors: bool = False,
    ) -> bool:
        if not self.matching_route or not self.controller or (action and action != self.matching_route.action):
            return False

        self._log_action(self.controller, self.matching_route.action)

        try:
            if params is None:
                params = self.controller.get_params("all", ignore_errors=ignore_param_errors)

            await self.matching_route.call_action(self.controller, params)
            return True

        except (ParamDecodeError, ActionDispatchError, Exception) as err:
            raise err

    async def _invoke_default_action(
        self,
        action: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
        ignore_param_errors: bool = False,
    ) -> bool:
        if not action:
            raise ValueError("ActionHandler cannot find a matching route to determine 'action' (it cannot be None)")

        if not hasattr(self.default_controller, action) or not callable(getattr(self.default_controller, action)):
            return False

        self._log_action(self.default_controller, action)
        action_func = getattr(self.default_controller, action)

        try:
            if params is None:
                params = self.default_controller.get_params("all", ignore_errors=ignore_param_errors)

            if iscoroutinefunction(action_func):
                await action_func(**params)
            else:
                action_func(**params)

            return True

        except TypeError as err:
            # pylint: disable=no-else-raise
            if err.__traceback__ and err.__traceback__.tb_next is None:
                # If calling the action fails because the request does not match the action's method signature,
                # raise an ActionDispatchError
                raise ActionDispatchError(str(err)) from None
            else:
                # Any other TypeError is raised by the action itself, so do not intercept
                raise err

        except (ParamDecodeError, Exception) as err:
            raise err

    async def _invoke_action(
        self,
        action: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
        ignore_param_errors: bool = False,
    ) -> None:
        try:
            # Attempt to invoke the action of the route which matches the request; return if successful
            if await self._invoke_route_action(action, params, ignore_param_errors):
                return
            # If the appropriate route for the request could be determined, or if the given 'action' differs from the
            # route action, fall back on the default controller (below)
        except ActionDispatchError as err:
            # If the request does not match the action's method signature, get request metadata in the context of
            # the matched route before trying to find an action with the same name in the default controller
            action = self.matching_route.action  # type: ignore
            params = self.controller.get_params("all", ignore_errors=ignore_param_errors)  # type: ignore

            # If the action of the matched route also exists in the default controller, log this condition and fall
            # back on the default controller (below); otherwise surface the ActionDispatchError to caller
            if hasattr(self.default_controller, action) and callable(getattr(self.default_controller, action)):  # type: ignore
                logger.debug("Invocation of '%s' action failed, falling back on default controller", action)
            else:
                raise err
        except (ParamDecodeError, Exception) as err:
            # Surface any errors caused by malformed parameters or uncaught exceptions raised in the body of the action
            raise err

        # As the action could not be invoked using a matching route and controller, attempt to invoke it using the
        # default controller instead
        try:
            if not await self._invoke_default_action(action, params, ignore_param_errors):
                # If the action cannot be found in the default controller, raise an error
                raise ActionUndefined(f"The default controller has no '{action}' action")

        except (ActionUndefined, ParamDecodeError, ActionDispatchError, Exception) as err:
            # Surface all errors which occur while invoking the action on the default controller
            raise err

    def _invoke_action_sync(
        self,
        action: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
        ignore_param_errors: bool = False,
    ) -> None:
        coroutine = self._invoke_action(action, params, ignore_param_errors)

        while True:
            try:
                coroutine.send(None)
            except StopIteration:
                return

    def _handle_incomplete_action(self, action_fallback: bool = True) -> None:
        if self.finished:
            return

        controller, action = self.action_call_stack[-1]

        try:
            raise ActionIncompleteError(
                f"action '{action}' in controller '{controller.__class__.__name__}' did not produce a response"
            )
        except ActionIncompleteError as err:
            self._log_exception(err)

        if action_fallback:
            self._invoke_action_sync("incomplete_action", ignore_param_errors=True)

            # Handle the situation in which the "incomplete_action" action itself fails to produce a response
            if not self.finished:
                self._handle_incomplete_action(action_fallback=False)
                self.default_controller.send_response(500)

    def _process_request_id(self) -> None:
        # Make incoming request ID available to logger
        keylime_logging.request_id_var.set(self.request_id)
        # Set response header to include request ID
        self.set_header("X-Request-ID", self.request_id)

    def initialize(self, server: "Server") -> None:
        # The initialize method is provided by RequestHandler to be used instead of overriding __init__
        # pylint: disable=attribute-defined-outside-init

        self._server: Server = server
        self._matching_route: Optional["Route"] = None
        self._controller: Optional["Controller"] = None
        self._default_controller: "Controller" = DefaultController(self)
        self._action_call_stack: list[tuple["Controller", str]] = []
        self._received_at: int = time.time_ns()
        self._finished: bool = False

    async def prepare(self) -> None:
        # Tornado allows the prepare method to be overridden as async in subclasses of RequestHandler
        # pylint: disable=invalid-overridden-method

        # Accept optional request ID to track the lifecycle of the request
        self._process_request_id()
        # Log incoming request
        logger.info("%s %s", self.request.method, self.request.path)
        # Find highest-priority route which matches the request
        route = self.server.first_matching_route(self.request.method, self.request.path)

        # Handle situations in which a matching route does not exist
        if not route:
            # Check if any route with that path exists
            route_with_path = self.server.first_matching_route(None, self.request.path)

            # Produce error response using an appropriate error-handling action
            if route_with_path:
                await self._invoke_action("method_not_allowed", ignore_param_errors=True)
            else:
                await self._invoke_action("not_found", ignore_param_errors=True)

            return

        # Handle situation where HTTP is used to access an HTTPS-only route
        if self.request.protocol == "http" and not route.allow_insecure:
            await self._invoke_action("https_required", ignore_param_errors=True)

        # Below warning is a false positive: self._matching_route and self._controller are first defined in initialize
        # pylint: disable=attribute-defined-outside-init

        # Save found route in object attribute
        self._matching_route = route
        # Create a new instance of the controller for the current ActionHandler instance
        self._controller = route.new_controller(self)

    async def process_request(self) -> None:
        # If a route matches the request, invoke action determined by the matching route
        if self.matching_route and self.controller:
            try:
                await self._invoke_action()
            except ParamDecodeError:
                # If the query, form or JSON parameters are malformed, respond using error-handling action
                await self._invoke_action("malformed_params", ignore_param_errors=True)
            except ActionDispatchError:
                # If the union of path, query, form and JSON parameters and do not match the method signature
                # of the action, respond using error-handling action
                await self._invoke_action("action_dispatch_error", ignore_param_errors=True)
            except Exception as err:
                # Any other exception which is not caught within the action body should be logged as an unexpected error
                # before responding using error-handling action
                self._log_exception(err)
                await self._invoke_action("action_exception", ignore_param_errors=True)

        # Handle situation in which no invoked action produces a response
        self._handle_incomplete_action()

    def write_error(self, status_code: int, **kwargs: Any) -> None:
        if status_code == 405 and kwargs.get("exc_info"):
            # Handle situation in which the HTTP method given in the request is not supported by the server (Tornado
            # produces a 405 error by default in this case)

            # self.prepare() is not triggered in this case, so perform request reporting tasks
            self._process_request_id()
            logger.info("%s %s", self.request.method, self.request.path)
            # Produce a response using the appropriate error-handling action
            self._invoke_action_sync("unsupported_method", ignore_param_errors=True)

        elif kwargs.get("exc_info"):
            # For any other exception produced by this class and not caught elsewhere, log the exception and invoke
            # the appropriate error-handling action
            _, err, _ = kwargs["exc_info"]
            self._log_exception(err)
            self._invoke_action_sync("handler_exception", ignore_param_errors=True)

        else:
            # Catch-all for all other errors (typically those produced by calling Tornado's send_error method)
            self.default_controller.send_response(status_code)

        # Handle situation in which none of the above-invoked error-handling actions produce a response
        self._handle_incomplete_action()

    def on_finish(self) -> None:
        message = f"Sent {self.get_status()} in {self.elapsed_time}"

        if self.get_status() < 400:
            # Log 100, 200 and 300 series responses as informational
            logger.info(message)
        elif self.get_status() < 500:
            # Log 400 series responses as warnings
            logger.warning(message)
        else:
            # Log 500 series responses as errors
            logger.error(message)

        self._finished = True

    async def get(self) -> None:
        await self.process_request()

    async def head(self) -> None:
        await self.process_request()

    async def post(self) -> None:
        await self.process_request()

    async def put(self) -> None:
        await self.process_request()

    async def patch(self) -> None:
        await self.process_request()

    async def delete(self) -> None:
        await self.process_request()

    async def options(self) -> None:
        await self.process_request()

    @property
    def server(self) -> "Server":
        return self._server

    @property
    def matching_route(self) -> Optional["Route"]:
        return self._matching_route

    @property
    def controller(self) -> Optional["Controller"]:
        return self._controller

    @property
    def default_controller(self) -> "Controller":
        return self._default_controller

    @property
    def action_call_stack(self) -> list[tuple["Controller", str]]:
        return self._action_call_stack.copy()

    @property
    def finished(self) -> bool:
        return self._finished

    @property
    def elapsed_time(self) -> str:
        # pylint: disable=no-else-return

        ns_elapsed = time.time_ns() - self._received_at

        if ns_elapsed < 1000:
            return f"{ns_elapsed}ns"
        elif ns_elapsed < 1000000:
            return f"{round(ns_elapsed/1000)}μs"
        elif ns_elapsed < 1000000000:
            return f"{round(ns_elapsed/1000000)}ms"
        else:
            return f"{round(ns_elapsed/1000000000)}s"

    @property
    def request_id(self) -> str:
        request_id = self.request.headers.get("X-Request-ID") or ""
        request_id = re.sub(r"\W+", "", request_id)
        request_id = request_id[:36]
        return request_id
