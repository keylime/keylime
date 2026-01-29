import re
import time
import traceback
from inspect import iscoroutinefunction
from typing import TYPE_CHECKING, Any, Mapping, Optional

from tornado.web import RequestHandler

from keylime import keylime_logging
from keylime.authorization.manager import get_authorization_manager
from keylime.authorization.provider import Action, AuthorizationRequest
from keylime.models.base.types import Timestamp  # type: ignore[attr-defined]
from keylime.models.verifier.auth_session import AuthSession
from keylime.web.base.default_controller import DefaultController
from keylime.web.base.exceptions import (
    ActionDispatchError,
    ActionIncompleteError,
    ActionUndefined,
    ParamDecodeError,
    RequiredContentMissing,
    StopAction,
)

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

        try:
            formatted_tb = traceback.format_exception(err)
        except NameError:
            # Sometimes an exception cannot be printed with traceback.format_exception() for unknown reasons.
            # If this occurs, manually construct the output using traceback.format_tb()
            formatted_tb = ["Traceback (most recent call last):\n"]
            formatted_tb.extend(traceback.format_tb(err.__traceback__))
            formatted_tb.append(f"{type(err).__name__}: {str(err)}")

        # Take the list of strings returned by format_exception, where each string ends in a newline and may contain
        # internal newlines, and split the concatenation of all the strings by newline
        message = "".join(formatted_tb)
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

    def _extract_identity(self) -> tuple[str, str]:
        """Extract identity from bearer token or mTLS certificate.

        Authentication methods are mutually exclusive and determined by the
        presence of an Authorization header:

        - Authorization header present → agent authentication path
          - Valid bearer token → identity_type = "agent"
          - Invalid/expired token → identity_type = "anonymous" (denied)
          - NEVER falls back to mTLS (prevents privilege escalation)

        - No Authorization header → admin authentication path
          - Valid mTLS certificate → identity_type = "admin"
          - No certificate → identity_type = "anonymous"

        Security Model:
            Agents authenticate via PoP (Proof-of-Possession) bearer tokens only.
            Admins authenticate via mTLS client certificates only.

            IMPORTANT: Never distribute client certificates signed by the verifier's
            trusted CA to agents. Agents should only have PoP tokens. If an agent
            had a valid client certificate AND didn't send an Authorization header,
            they would be identified as an admin.

            Certificate Requirements:
            - Pull mode agents: Self-signed server certs are acceptable (trust comes
              from TPM quote). If CA-issued, must have Server Authentication EKU only.
            - Push mode agents: Never use client certs from trusted CA. Use PoP
              tokens only.
            - Admins: Client certs signed by trusted CA with Client Authentication EKU.

        Returns:
            Tuple of (identity, identity_type) where:
            - identity: The identifier (agent_id from token, CN from cert, or "anonymous")
            - identity_type: One of:
                - "agent": PoP bearer token present and valid (agent_id)
                - "admin": mTLS certificate present, no Authorization header
                - "anonymous": No valid authentication
        """
        auth_header = self.request.headers.get("Authorization")

        # If Authorization header is present, this is an agent authentication attempt
        # We NEVER fall back to mTLS - this prevents privilege escalation attacks
        if auth_header:
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                # Look up by token hash (tokens are never stored in plaintext)
                auth_session = AuthSession.get_by_token(token)
                if auth_session and auth_session.agent_id:  # type: ignore[attr-defined]
                    # Check if token is still valid
                    now = Timestamp.now()
                    if auth_session.token_expires_at >= now:  # type: ignore[attr-defined]
                        logger.debug("Extracted agent identity from bearer token: %s", auth_session.agent_id)  # type: ignore[attr-defined]
                        return (auth_session.agent_id, "agent")  # type: ignore[attr-defined]
                    logger.debug("Bearer token expired for agent: %s", auth_session.agent_id)  # type: ignore[attr-defined]
                else:
                    logger.debug("Invalid bearer token provided")
            else:
                logger.debug("Malformed Authorization header (expected 'Bearer <token>')")

            # Authorization header present but invalid - return anonymous, do NOT try mTLS
            return ("anonymous", "anonymous")

        # No Authorization header - check for mTLS certificate (admin authentication)
        try:
            cert_dict = self.request.get_ssl_certificate()
            if cert_dict and isinstance(cert_dict, dict):
                # Extract CN (Common Name) from subject
                cn = None
                subject = cert_dict.get("subject", ())
                for rdn in subject:
                    for name_tuple in rdn:
                        if name_tuple[0] == "commonName":
                            cn = name_tuple[1]
                            break
                    if cn:
                        break

                if cn:
                    # Extract SAN (Subject Alternative Name) for enhanced logging
                    san_info = self._extract_san_from_cert(cert_dict)
                    if san_info:
                        logger.debug(
                            "Extracted admin identity from mTLS certificate: CN=%s, SAN={%s}",
                            cn,
                            san_info,
                        )
                    else:
                        logger.debug("Extracted admin identity from mTLS certificate: CN=%s", cn)
                    return (cn, "admin")
        except Exception as e:
            logger.debug("Failed to extract mTLS certificate: %s", e)

        # No authenticated identity found
        return ("anonymous", "anonymous")

    def _extract_san_from_cert(self, cert_dict: dict[Any, Any]) -> str:
        """Extract Subject Alternative Name (SAN) information from certificate.

        Extracts email, DNS, and URI entries from the certificate's SAN extension
        for enhanced audit logging.

        Args:
            cert_dict: Certificate dictionary from get_ssl_certificate()

        Returns:
            Formatted string with SAN entries, or empty string if no SAN found
        """
        san_entries = []
        subject_alt_name = cert_dict.get("subjectAltName", ())

        for san_type, san_value in subject_alt_name:
            # Include email, DNS, URI, and IP Address entries
            if san_type in ("email", "DNS", "URI", "IP Address"):
                san_entries.append(f"{san_type}={san_value}")

        return ", ".join(san_entries)

    def _get_action_from_route(self) -> Optional[Action]:
        """Get the authorization Action for the current route.

        Returns:
            Action enum value from route metadata, or None if not set
        """
        if not self.matching_route:
            return None

        return self.matching_route.auth_action

    def _get_resource_from_route(self) -> Optional[str]:
        """Extract resource identifier from the matched route path.

        Returns:
            Resource identifier (e.g., agent_id, policy name) or None
        """
        if not self.matching_route:
            return None

        try:
            # Extract path parameters from the matched route
            params = self.matching_route.capture_params(self.request.path)

            # Priority order: agent_id > name > session_id
            if "agent_id" in params:
                return params["agent_id"]
            if "name" in params:
                return params["name"]
            if "session_id" in params:
                return params["session_id"]

            return None
        except Exception as e:
            logger.debug("Failed to extract resource from route: %s", e)
            return None

    def _check_authorization(self) -> bool:
        """Check if the current request is authorized.

        Returns:
            True if authorized, False if denied (response already sent)
        """
        # Skip authorization check if route doesn't require auth
        if not self.matching_route or not self.matching_route.requires_auth:
            return True

        # Extract identity from request
        identity, identity_type = self._extract_identity()

        # Get action from route
        action = self._get_action_from_route()
        if not action:
            # Could not map route to action - deny by default (fail-safe)
            logger.error(
                "Authorization denied: could not map route to action: %s %s",
                self.request.method,
                self.request.path,
            )
            self.set_status(403)
            self.write(
                {
                    "errors": [
                        {
                            "status": "403",
                            "title": "Forbidden",
                            "detail": "Could not determine required permissions for this operation",
                        }
                    ]
                }
            )
            self.finish()
            return False

        # Get resource from route
        resource = self._get_resource_from_route()

        # Create authorization request
        auth_request = AuthorizationRequest(
            identity=identity, identity_type=identity_type, action=action, resource=resource
        )

        # Call authorization manager for this component
        try:
            auth_manager = get_authorization_manager(self.server.component)
            auth_response = auth_manager.authorize(auth_request)

            if not auth_response.allowed:
                # Authorization denied
                logger.warning(
                    "Authorization denied: identity=%s, action=%s, resource=%s, reason=%s",
                    identity,
                    action.value,
                    resource,
                    auth_response.reason,
                )
                self.set_status(403)
                self.write(
                    {
                        "errors": [
                            {
                                "status": "403",
                                "title": "Forbidden",
                                "detail": auth_response.reason,
                            }
                        ]
                    }
                )
                self.finish()
                return False

            # Authorization granted
            logger.debug(
                "Authorization granted: identity=%s, action=%s, resource=%s",
                identity,
                action.value,
                resource,
            )
            return True

        except Exception as e:
            # Authorization manager error - fail safe (deny)
            logger.error("Authorization check failed with error: %s", e, exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "errors": [
                        {
                            "status": "500",
                            "title": "Internal Server Error",
                            "detail": "Authorization system error",
                        }
                    ]
                }
            )
            self.finish()
            return False

    def _validate_authentication(self) -> bool:
        """Validate the authentication token from the Authorization header.

        Returns True if authentication is valid or not required, False if authentication failed.
        Sets HTTP 401 response if token is invalid or expired.
        """
        # Check if route requires authentication
        # Session creation routes (POST/PATCH /sessions) don't require authentication
        if self.request.method in ["POST", "PATCH"] and "/sessions" in self.request.path:
            return True

        # Extract token from Authorization header
        auth_header = self.request.headers.get("Authorization")
        if not auth_header:
            # No Authorization header is expected for admin (mTLS) and public
            # requests. This method only validates bearer tokens when present;
            # the authorization layer (_check_authorization) is responsible for
            # enforcing access control based on the extracted identity, which
            # will be "admin" (mTLS cert) or "anonymous" (no credentials).
            return True

        # Parse Bearer token
        if not auth_header.startswith("Bearer "):
            logger.warning("Invalid Authorization header format (expected 'Bearer <token>')")
            self.set_status(401)
            self.write(
                {
                    "errors": [
                        {"status": "401", "title": "Unauthorized", "detail": "Invalid Authorization header format"}
                    ]
                }
            )
            self.finish()
            return False

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Look up token by hash in database
        auth_session = AuthSession.get_by_token(token)
        if not auth_session:
            logger.warning("Authentication token not found (hash prefix: %s...)", token[:8] if token else "")
            self.set_status(401)
            self.write(
                {"errors": [{"status": "401", "title": "Unauthorized", "detail": "Invalid authentication token"}]}
            )
            self.finish()
            return False

        # Check if token has expired
        now = Timestamp.now()
        if auth_session.token_expires_at < now:  # type: ignore[attr-defined]
            logger.info(
                "Authentication token expired for agent '%s' (expired at %s)",
                auth_session.agent_id,  # type: ignore[attr-defined]
                auth_session.token_expires_at,  # type: ignore[attr-defined]
            )
            self.set_status(401)
            self.write(
                {"errors": [{"status": "401", "title": "Unauthorized", "detail": "Authentication token expired"}]}
            )
            self.finish()
            return False

        # Token is valid
        logger.debug("Authentication token validated for agent '%s'", auth_session.agent_id)  # type: ignore[attr-defined]
        return True

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
            return

        # Below warning is a false positive: self._matching_route and self._controller are first defined in initialize
        # pylint: disable=attribute-defined-outside-init

        # Save found route in object attribute
        self._matching_route = route
        # Create a new instance of the controller for the current ActionHandler instance
        self._controller = route.new_controller(self)

        # Validate authentication token if provided
        if not self._validate_authentication():
            # Authentication failed, response already sent
            return

        # Check authorization
        if not self._check_authorization():
            # Authorization denied, response already sent
            return

    async def process_request(self) -> None:
        # If a route matches the request, invoke action determined by the matching route
        if self.matching_route and self.controller:
            try:
                await self._invoke_action()
            except StopAction:
                # If the action is terminated early, continue
                pass
            except ParamDecodeError:
                # If the query, form or JSON parameters are malformed, respond using error-handling action
                await self._invoke_action("malformed_params", ignore_param_errors=True)
            except ActionDispatchError:
                # If the union of path, query, form and JSON parameters and do not match the method signature
                # of the action, respond using error-handling action
                await self._invoke_action("action_dispatch_error", ignore_param_errors=True)
            except RequiredContentMissing:
                # If a decorator from the Controller class has been used to mark a certain content format as required
                # for the action and the request body or Content-Type do not adhere, respond using error-handling action
                await self._invoke_action("format_not_allowed", ignore_param_errors=True)
            except Exception as err:
                # Any other exception which is not caught within the action body should be logged as an unexpected
                # internal error before responding using error-handling action
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
