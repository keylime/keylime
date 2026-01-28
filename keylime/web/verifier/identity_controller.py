"""Controller for on-demand identity verification.

This controller handles identity verification requests, which verify that a
TPM quote was produced by a genuine TPM. This is separate from evidence
verification which validates the actual attestation evidence.

Identity verification is a PUBLIC action - it allows any party to verify
that a TPM quote is genuine without requiring authentication.
"""

from keylime.web.base import Controller


class IdentityController(Controller):
    """Controller for on-demand identity verification.

    This controller handles verification that a TPM quote was produced by a
    genuine TPM (identity verification). It does not verify the attestation
    evidence itself - for that, use EvidenceController.

    All actions in this controller are PUBLIC (no authentication required).
    """

    def _new_v2_handler(self):
        """Create a legacy v2 VerifyIdentityHandler."""
        # pylint: disable=import-outside-toplevel  # Avoid circular import
        from keylime import cloud_verifier_tornado as v2

        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.VerifyIdentityHandler(tornado_app, tornado_req, override=self.action_handler)  # type: ignore[no-untyped-call]

    # GET /v2[.x]/verify/identity
    def verify(self, **_params):
        """Verify that a TPM quote was produced by a genuine TPM.

        This is a PUBLIC action - no authentication required.

        For API v2, delegates to the legacy VerifyIdentityHandler.
        For API v3+, returns 404 (not yet implemented).
        """
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation
