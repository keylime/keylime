from typing import Any

from keylime.web.base import Controller


class MBRefStateController(Controller):
    def _new_v2_handler(self) -> Any:
        # pylint: disable=import-outside-toplevel  # Avoid circular import
        from keylime import cloud_verifier_tornado as v2

        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.MbpolicyHandler(tornado_app, tornado_req, override=self.action_handler)  # type: ignore[no-untyped-call]

    # GET /v3[.x]/refstates/uefi/
    # GET /v2[.x]/mbpolicies/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # GET /v3[.x]/refstates/uefi/:name
    # GET /v2[.x]/mbpolicies/:name
    def show(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # POST /v3[.x]/refstates/uefi/
    # POST /v2[.x]/mbpolicies/:name
    def create(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().post()  # type: ignore[no-untyped-call]
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    # PATCH /v3[.x]/refstates/uefi/:name
    def update(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self.respond(404)
        # TODO: Replace with v3 implementation

    # PUT /v2[.x]/mbpolicies/:name
    def overwrite(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._new_v2_handler().put()  # type: ignore[no-untyped-call]

    # DELETE /v3[.x]/refstates/uefi/:name
    # DELETE /v2[.x]/mbpolicies/:name
    def delete(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().delete()  # type: ignore[no-untyped-call]
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation
