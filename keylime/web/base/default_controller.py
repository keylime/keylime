from typing import Any

from keylime.web.base.controller import Controller


class DefaultController(Controller):
    def not_found(self, **_params: Any) -> None:
        self.send_response(404, "Not Found")

    def method_not_allowed(self, **_params: Any) -> None:
        self.send_response(405, "Method Not Allowed")

    def unsupported_method(self, **_params: Any) -> None:
        # The default behaviour of Tornado is to return a 405 error if an unsupported method is used in a request but,
        # according to RFC 9110, a 501 should be used instead
        self.send_response(501, "Not Implemented")

    def https_required(self, **_params: Any) -> None:
        self.send_response(400, "Bad Request")

    def malformed_params(self, **_params: Any) -> None:
        self.send_response(400, "Malformed Request Parameter")

    def action_dispatch_error(self, **_param: Any) -> None:
        self.send_response(400, "Bad Request")

    def action_exception(self, **_param: Any) -> None:
        self.send_response(500, "Internal Server Error")

    def incomplete_action(self, **_param: Any) -> None:
        self.send_response(500, "Internal Server Error")

    def handler_exception(self, **_param: Any) -> None:
        self.send_response(500, "Internal Server Error")
