from keylime.web.base.controller import Controller


class DefaultController(Controller):
    def not_found(self, **params):
        self.send_response(404, "Not Found")

    def method_not_allowed(self, **params):
        self.send_response(405, "Method Not Allowed")

    def https_required(self, **params):
        self.send_response(400, "Bad Request")
