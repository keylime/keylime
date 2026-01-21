import asyncio
import multiprocessing
from abc import ABC, abstractmethod
from functools import wraps
from ssl import CERT_OPTIONAL
from typing import TYPE_CHECKING, Any, Callable, Optional

import tornado

from keylime import api_version, config, keylime_logging, web_util
from keylime.web.base.action_handler import ActionHandler
from keylime.web.base.route import Route

# from keylime.web.base.stats_collector import StatsCollector

if TYPE_CHECKING:
    from ssl import SSLContext

    from keylime.authorization.provider import Action
    from keylime.web.base.controller import Controller

logger = keylime_logging.init_logging("web")


class Server(ABC):
    """The Server abstract class provides a domain-specific language (DSL) for defining an HTTP server with a set of
    specific endpoints. This is translated into a list of routes (see the ``Route`` class) which is ordered according to
    priority and can be matched against incoming requests based on their HTTP method and URL path.

    Example
    -------

    To use the Server class, inherit from it and implement the required ``_routes`` method::

        class ExampleServer(Server):
            def _routes(self):
                self._get("/", ExampleController, "example_action")
                # (Any additional routes...)

    Routes are defined by calling the ``self._get(...)``, ``self._post(...)``, ``self._put(...)``, etc. helper methods.
    These calls must happen within the ``_routes`` method or a method which is called by ``_routes``. Each helper method
    takes a path pattern, controller and action. For more details on these parameters, refer to the documentation for
    the ``Route`` class.

    In the event that multiple routes apply to a single request, routes defined earlier will take priority
    over routes defined later.

    Once a server is defined by subclassing Server as above, it can be used by creating a new instance and calling
    the ``start`` instance method::

        server = ExampleServer()
        server.start()

    To spawn multiple worker processes for handling requests, you can call Tornado's ``fork_processes`` function after
    instantiating the server, but before starting it:

        server = ExampleServer()
        tornado.process.fork_processes(0)
        server.start()

    Decorators
    ----------

    The Server class also provides decorators which can be used to modify routes defined using the helper methods,
    or generate additional routes automatically. These decorators can be applied directly to the routes defined
    in the ``_routes`` method or to a subset of routes by extracting them into their own method::

        class ExampleServer(Server):
            def _routes(self):
                self._v2_routes()
                self._get("/", HomeController, "index")

            @Server.version_scope(2)
            def _v2_routes(self):
                self._get("/agents", AgentsController, "index")
                self._get("/agents/:id", AgentsController, "show")

    The above example, in which ``@Server.version_scope(2)`` is applied to the ``_v2_routes`` method, is equivalent
    to defining all routes manually as follows:

        class ExampleServer(Server):
            def _routes(self):
                self._get("/v2/agents", AgentsController, "index")
                self._get("/v2.:minor/agents", AgentsController, "index")
                self._get("/v2/agents/:id", AgentsController, "show")
                self._get("/v2.:minor/agents/:id", AgentsController, "show")
                self._get("/", HomeController, "index")

    Notice that the ``"index"`` and ``"show"`` actions of ``AgentsController`` will now handle requests made to version
    2 of the API, regardless of whether a minor version is specified or not.
    """

    @staticmethod
    def _new_scoped_route(pattern_prefix: str, route: Route) -> Route:
        pattern = pattern_prefix + route.pattern
        return Route(
            route.method,
            pattern,
            route.controller,
            route.action,
            route.allow_insecure,
            route.requires_auth,
            route.auth_action,
        )

    @staticmethod
    def _make_versioned_routes(major_version: int, route: Route) -> list[Route]:
        versioned_routes = [Server._new_scoped_route(f"/v{major_version}", route)]
        versioned_routes = versioned_routes + [
            Server._new_scoped_route(f"/v{version}", route)
            for version in api_version.all_versions()
            if api_version.major(version) == major_version
        ]
        return versioned_routes

    @staticmethod
    def version_scope(major_version: int) -> Callable[..., Callable[..., Any]]:
        # pylint: disable=protected-access, unused-private-member

        # Create a decorator which will scope routes to major_version
        def version_scope_decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            # Create a wrapper function which will take the place of the decorated function (func)
            @wraps(func)  # preserves the name and module of func when introspected
            def version_scope_wrapper(obj: Server, *args: Any, **kwargs: Any) -> Any:
                if not isinstance(obj, Server):
                    raise TypeError(
                        "The @Server.version_scope(major_version) decorator can only be used on methods of a class "
                        "which inherits from Server"
                    )

                # Get the routes defined at the time that the decorator is called
                initial_routes = obj.routes
                # Create a new list to hold the routes to be added to the Server
                new_routes_list = []
                # Call the decorated function and get the return value (typically None)
                value = func(obj, *args, **kwargs)

                # Iterate over routes created so far
                for route in obj.routes:
                    # Check that the current route is a route newly created by the decorated function
                    if route not in initial_routes:
                        # Define routes scoped to the API version specified by major_version
                        new_routes_list.extend(Server._make_versioned_routes(major_version, route))

                # Replace the Server instance's list of routes with a new list consisting of the routes which were
                # present before func was called and the new routes scoped to major_version
                obj.__routes = initial_routes + new_routes_list

                # Return the return value of the decorated function in case it is something other than None
                return value

            return version_scope_wrapper

        return version_scope_decorator

    @staticmethod
    def push_only(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)  # preserves the name and module of func when introspected
        def push_only_wrapper(obj: Server, *args: Any, **kwargs: Any) -> Any:
            if not isinstance(obj, Server):
                raise TypeError(
                    "the @Server.push_only decorator can only be used on methods of a class which inherits from Server"
                )

            if not obj.operating_mode:
                raise TypeError("the @Server.push_only decorator cannot be used when no 'operating_mode' is set")

            if obj.operating_mode == "push":
                return func(obj, *args, **kwargs)
            return None

        return push_only_wrapper

    @staticmethod
    def pull_only(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)  # preserves the name and module of func when introspected
        def pull_only_wrapper(obj: Server, *args: Any, **kwargs: Any) -> Any:
            if not isinstance(obj, Server):
                raise TypeError(
                    "The @Server.pull_only decorator can only be used on methods of a class which inherits from Server"
                )

            if not obj.operating_mode:
                raise TypeError("the @Server.pull_only decorator cannot be used when no 'operating_mode' is set")

            if obj.operating_mode == "pull":
                return func(obj, *args, **kwargs)
            return None

        return pull_only_wrapper

    def __init__(self, **options: Any) -> None:
        """Initialise server with provided configuration options or default values and bind to sockets for HTTP and/or
        HTTPS connections. This does not start the server to start accepting requests (this is done by calling the
        ``server.start()`` instance method).

        If you wish to create multiple server processes, first instantiate a new server and then fork the process
        before starting the server with `server.start()`.
        """
        # Set defaults for server options
        self.__component: str = "unknown"  # Component name (e.g., "verifier", "registrar")
        self.__config_component: str | None = None
        self.__operating_mode = None
        self.__bind_interface: str = "127.0.0.1"
        self.__http_port: Optional[int] = 80
        self.__https_port: Optional[int] = 443
        self.__max_upload_size: Optional[int] = 104857600  # 100MiB
        self.__ssl_ctx: Optional["SSLContext"] = None
        self.__worker_count: Optional[int] = 0

        # Override defaults with values given by the implementing class
        self._setup()

        # If options are set by the caller, use these to override the defaults and those set by the implementing class
        for opt in ["operating_mode", "bind_interface", "http_port", "https_port", "max_upload_size", "ssl_ctx"]:
            if opt in options:
                setattr(self, f"__{opt}", options[opt])

        if not self.bind_interface:
            raise ValueError(
                f"server '{self.__class__.__name__}' cannot be initialised without a value for 'bind_interface'"
            )

        if not self.http_port and (not self.https_port or not self.ssl_ctx):
            raise ValueError(
                f"server '{self.__class__.__name__}' cannot be initialised without either 'http_port' or 'https_port'"
                f"and 'ssl_ctx'"
            )

        # Initialise empty list for routes
        self.__routes: list[Route] = []
        # Add routes defined by the implementing class
        self._routes()

        # Create new Tornado app with request handler to process routes
        self.__tornado_app = tornado.web.Application([(r".*", ActionHandler, {"server": self})])

        # Bind socket for HTTP connections
        if self.http_port:
            self.__tornado_http_sockets = tornado.netutil.bind_sockets(int(self.http_port), self.bind_interface)
        else:
            self.__tornado_http_sockets = []

        # Bind socket for HTTPS connections
        if self.https_port:
            self.__tornado_https_sockets = tornado.netutil.bind_sockets(int(self.https_port), self.bind_interface)
        else:
            self.__tornado_https_sockets = []

        # Tornado servers are instantiated by calling start_single() or start_multi(), so set to None initially
        self.__tornado_http_server: Optional[tornado.httpserver.HTTPServer] = None
        self.__tornado_https_server: Optional[tornado.httpserver.HTTPServer] = None

    async def start_single(self) -> None:
        """Instantiates and starts the server (with one Tornado HTTPServer instance to handle HTTP connections
        and another to handle HTTPS connections).

        This should be done once per process. When new processes are created by forking, this method
        should be called after the fork.
        """
        if self.__tornado_http_sockets:
            http_server = tornado.httpserver.HTTPServer(
                self.__tornado_app, ssl_options=None, max_buffer_size=self.max_upload_size
            )
            http_server.add_sockets(self.__tornado_http_sockets)
            self.__tornado_http_server = http_server

        if self.__tornado_https_sockets and self.ssl_ctx:
            https_server = tornado.httpserver.HTTPServer(
                self.__tornado_app, ssl_options=self.ssl_ctx, max_buffer_size=self.max_upload_size
            )
            https_server.add_sockets(self.__tornado_https_sockets)
            self.__tornado_https_server = https_server

        await asyncio.Event().wait()

    def start_multi(self) -> None:
        ports = ""
        protocols = ""

        if self.__tornado_http_sockets:
            ports = str(self.http_port)
            protocols = "HTTP"

        if self.__tornado_https_sockets and self.ssl_ctx:
            ports = f"{ports}/{self.https_port}" if ports else f"{self.https_port}"
            protocols = f"{protocols}/S" if protocols else "HTTPS"

        logger.info(
            "Listening on %s:%s (%s) with %s worker processes...",
            self.bind_interface,
            ports,
            protocols,
            self.worker_count,
        )

        # with StatsCollector():
        # num = manager.Value('i', 0)
        tornado.process.fork_processes(self.worker_count)
        # num.value = num.value + 1
        # print(num.value)
        asyncio.run(self.start_single())

    def _setup(self) -> None:
        """Defines values to use in place of the defaults for the various server options. It is suggested that this is
        overriden by the implementing class."""

    @abstractmethod
    def _routes(self) -> None:
        """Defines the routes accepted the server. Must be overridden by the implementing class and include one
        or more calls to the ``_get``, ``_head``, ``_post``, ``_put``, ``_patch``, ``_delete`` and/or ``_options``
        helper methods."""

    def _use_config(self, component: str) -> None:
        """Sets config component (i.e., namespace) used to locate config values when setting server options."""
        self.__config_component = component

    def _set_option(self, name: str, **kwargs: Any) -> None:
        """Sets server option by name either from given value or by obtaining it from user config. If the value is
        falsy, uses the given fallback value instead or ``None`` if no fallback is provided. Examples::

            # Set option using provided value
            self._set_option("bind_interface", value="0.0.0.0")

            # Set option using integer value in config called "tls_port"
            self._set_option("https_port", from_config=("tls_port", int))

            # Set option with a fallback value
            self._set_option("max_upload_size", from_config=("max_upload_size", int), fallback=5000)

        Must call ``self._use_config(...)`` before setting options from config values.
        """

        attr_name = f"_Server__{name}"
        fallback = kwargs.get("fallback", None)

        if not hasattr(self, attr_name):
            raise ValueError(f"{self.__class__.__name__} has no option '{name}'")

        if "from_config" in kwargs and not self.config_component:
            raise ValueError(f"{self.__class__.__name__}._use_config() must be called before setting option '{name}'")

        if "fallback" in kwargs:
            del kwargs["fallback"]

        match kwargs:
            case {"value": value}:
                pass

            case {"from_config": config_name} if isinstance(config_name, str):
                value = config.get(self.config_component, config_name, fallback=fallback)  # type: ignore

            case {"from_config": (config_name, data_type)} if data_type is str:
                value = config.get(self.config_component, config_name, fallback=fallback)  # type: ignore

            case {"from_config": (config_name, data_type)} if data_type is int:
                value = config.getint(self.config_component, config_name, fallback=fallback)  # type: ignore

            case {"from_config": (config_name, data_type)} if data_type is float:
                value = config.getfloat(self.config_component, config_name, fallback=fallback)  # type: ignore

            case {"from_config": (config_name, data_type)} if data_type is bool:
                value = config.getboolean(self.config_component, config_name, fallback=fallback)  # type: ignore

            case _:
                raise TypeError(f"invalid arguments given when setting option '{name}' for {self.__class__.__name__}")

        setattr(self, attr_name, value or fallback)

    def _set_operating_mode(self, **kwargs: Any) -> None:
        """Sets operating mode of the server (push or pull)."""
        self._set_option("operating_mode", **kwargs)

    def _set_component(self, component: str) -> None:
        """Sets the component name for this server.

        The component name is used for component-aware authorization mappings.
        For example, the same route pattern may map to different actions
        depending on whether it's in the verifier or registrar.

        Args:
            component: Component name (e.g., "verifier", "registrar")
        """
        self.__component = component

    def _set_bind_interface(self, **kwargs: Any) -> None:
        """Sets the IP address or hostname to use to identify the network interface on which to listen for incoming
        requests. Examples::

            # Listen on all interfaces (receives connections from any address)
            self._set_bind_interface("bind_interface", value="0.0.0.0")

            # Listen on loopback interface (only receives connections from the local machine)
            self._set_bind_interface("bind_interface", value="localhost")
            self._set_bind_interface("bind_interface", value="127.0.0.1")

            # Listen on interface associated with a given hostname
            self._set_bind_interface("bind_interface", value="example.com")

            # Listen on interface specified in config
            self._set_bind_interface("bind_interface", from_config="interface")
        """

        self._set_option("bind_interface", **kwargs)

    def _set_http_port(self, **kwargs: Any) -> None:
        """Sets port on which to listen for HTTP requests."""

        if "from_config" in kwargs:
            kwargs.update({"from_config": (kwargs["from_config"], int)})

        self._set_option("http_port", **kwargs)

    def _set_https_port(self, **kwargs: Any) -> None:
        """Sets port on which to listen for HTTPS (HTTP over TLS) requests."""

        if "from_config" in kwargs:
            kwargs.update({"from_config": (kwargs["from_config"], int)})

        self._set_option("https_port", **kwargs)

    def _set_max_upload_size(self, **kwargs: Any) -> None:
        """Sets the maximum payload size in bytes that the server should accept in an HTTP request."""

        if "from_config" in kwargs:
            kwargs.update({"from_config": (kwargs["from_config"], int)})

        if "fallback" not in kwargs:
            kwargs.update({"fallback": 104857600})  # 100MiB

        self._set_option("max_upload_size", **kwargs)

    def _set_ssl_ctx(self, **kwargs: Any) -> None:
        """Sets the values used to secure TLS sessions. See https://docs.python.org/3/library/ssl.html#ssl.SSLContext"""

        if "from_config" in kwargs:
            raise TypeError(f"cannot set option 'ssl_ctx' for {self.__class__.__name__} using a single config value")

        self._set_option("ssl_ctx", **kwargs)

    def _set_default_ssl_ctx(self) -> None:
        """Generates the ssl_ctx using values from user config."""

        if not self.config_component:
            raise ValueError(f"{self.__class__.__name__}._use_config() must be called before generating 'ssl_ctx'")

        ssl_ctx = web_util.init_mtls(self.config_component)
        ssl_ctx.verify_mode = CERT_OPTIONAL
        self._set_option("ssl_ctx", value=ssl_ctx)

    def _get(
        self,
        pattern: str,
        controller: type["Controller"],
        action: str,
        allow_insecure: bool = False,
        requires_auth: bool = False,
        auth_action: Optional["Action"] = None,
    ) -> None:
        """Creates a new route to handle incoming GET requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("get", pattern, controller, action, allow_insecure, requires_auth, auth_action))

    def _head(
        self,
        pattern: str,
        controller: type["Controller"],
        action: str,
        allow_insecure: bool = False,
        requires_auth: bool = False,
        auth_action: Optional["Action"] = None,
    ) -> None:
        """Creates a new route to handle incoming HEAD requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("head", pattern, controller, action, allow_insecure, requires_auth, auth_action))

    def _post(
        self,
        pattern: str,
        controller: type["Controller"],
        action: str,
        allow_insecure: bool = False,
        requires_auth: bool = False,
        auth_action: Optional["Action"] = None,
    ) -> None:
        """Creates a new route to handle incoming POST requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("post", pattern, controller, action, allow_insecure, requires_auth, auth_action))

    def _put(
        self,
        pattern: str,
        controller: type["Controller"],
        action: str,
        allow_insecure: bool = False,
        requires_auth: bool = False,
        auth_action: Optional["Action"] = None,
    ) -> None:
        """Creates a new route to handle incoming PUT requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("put", pattern, controller, action, allow_insecure, requires_auth, auth_action))

    def _patch(
        self,
        pattern: str,
        controller: type["Controller"],
        action: str,
        allow_insecure: bool = False,
        requires_auth: bool = False,
        auth_action: Optional["Action"] = None,
    ) -> None:
        """Creates a new route to handle incoming PATCH requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("patch", pattern, controller, action, allow_insecure, requires_auth, auth_action))

    def _delete(
        self,
        pattern: str,
        controller: type["Controller"],
        action: str,
        allow_insecure: bool = False,
        requires_auth: bool = False,
        auth_action: Optional["Action"] = None,
    ) -> None:
        """Creates a new route to handle incoming DELETE requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("delete", pattern, controller, action, allow_insecure, requires_auth, auth_action))

    def _options(
        self,
        pattern: str,
        controller: type["Controller"],
        action: str,
        allow_insecure: bool = False,
        requires_auth: bool = False,
        auth_action: Optional["Action"] = None,
    ) -> None:
        """Creates a new route to handle incoming OPTIONS requests issued for paths which match the given
        pattern. Must be called from a Server subclass's ``self._routes`` method.
        """
        self.__routes.append(Route("options", pattern, controller, action, allow_insecure, requires_auth, auth_action))

    def first_matching_route(self, method: Optional[str], path: str) -> Optional[Route]:
        """Gets the highest-priority route which matches the given ``method`` and ``path``."""
        if method is None:
            matching_routes = (route for route in self.__routes if route.matches_path(path))
        else:
            matching_routes = (route for route in self.__routes if route.matches(method, path))

        try:
            return next(matching_routes)
        except StopIteration:
            return None

    @property
    def config_component(self) -> Optional[str]:
        return self.__config_component

    @property
    def component(self) -> str:
        """Get the component name for this server (e.g., 'verifier', 'registrar')."""
        return self.__component

    @property
    def operating_mode(self) -> Optional[str]:
        return self.__operating_mode

    @property
    def http_port(self) -> Optional[int]:
        return self.__http_port

    @property
    def https_port(self) -> Optional[int]:
        return self.__https_port

    @property
    def bind_interface(self) -> str:
        return self.__bind_interface

    @property
    def max_upload_size(self) -> Optional[int]:
        return self.__max_upload_size

    @property
    def ssl_ctx(self) -> Optional["SSLContext"]:
        return self.__ssl_ctx

    @property
    def worker_count(self) -> int:
        # pylint: disable=no-else-return

        if self.__worker_count == 0 or self.__worker_count is None:
            return multiprocessing.cpu_count()
        else:
            return self.__worker_count

    @property
    def routes(self) -> list[Route]:
        return self.__routes.copy()

    @property
    def tornado_http_server(self) -> Optional[tornado.httpserver.HTTPServer]:
        return self.__tornado_http_server

    @property
    def tornado_https_server(self) -> Optional[tornado.httpserver.HTTPServer]:
        return self.__tornado_https_server
