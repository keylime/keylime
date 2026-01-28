from keylime.web.base import Controller


class EvidenceController(Controller):
    """Controller for on-demand verification of attestation evidence.

    This controller handles evidence verification requests, which validate
    that attestation evidence (quotes, logs, etc.) is valid and trustworthy.

    For identity verification (verifying TPM genuineness), use IdentityController.

    All actions in this controller are PUBLIC (no authentication required).
    """

    def _new_v2_handler(self):
        """Create a legacy v2 VerifyEvidenceHandler."""
        # pylint: disable=import-outside-toplevel  # Avoid circular import
        from keylime import cloud_verifier_tornado as v2

        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.VerifyEvidenceHandler(tornado_app, tornado_req, override=self.action_handler)  # type: ignore[no-untyped-call]

    # POST /v3[.x]/verify/evidence
    def process(self, **_params):
        """Verify attestation evidence.

        This is a PUBLIC action - no authentication required.

        For API v2, delegates to the legacy VerifyEvidenceHandler.
        For API v3+, returns 404 (not yet implemented).
        """
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().post()  # type: ignore[no-untyped-call]
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation
