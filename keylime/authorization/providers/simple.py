"""Simple authorization provider for Keylime.

This provider implements a 4-category authorization policy for both the
verifier and registrar components:

- PUBLIC: No authentication required (info, evidence and identity verification,
  session creation, agent self-registration)
- AGENT_ONLY: Requires agent authentication (PoP token) AND resource ownership.
  Admins cannot access these endpoints (strict separation for attestation).
- AGENT_OR_ADMIN: Accessible by agents (with ownership) or admins (any resource).
  Example: agents can read their own status, admins can read any agent's status.
- ADMIN: Requires admin authentication (mTLS certificate)

This provider is intentionally simple. For fine-grained RBAC,
enterprise deployments should use OPA, LDAP, or a custom provider.

Future providers can use the full actions for granular control.

Security Model
--------------
Authentication and authorization are strictly separated by role:

- Agents authenticate via PoP (Proof-of-Possession) bearer tokens.
  They can only access AGENT endpoints and only for their own resources
  (identity must match the resource being accessed).

- Admins authenticate via mTLS client certificates signed by the
  verifier's trusted CA. They can access all ADMIN endpoints.

IMPORTANT: Never distribute client certificates signed by the verifier's
trusted CA to agents. This would allow agents to authenticate as admins
by simply not sending an Authorization header. The security model relies on:

1. Code: Authorization header presence blocks mTLS authentication fallback
2. Deployment: Only admins have client certs signed by the trusted CA

Certificate Requirements by Role:

- Pull mode agents: Self-signed server certificates are acceptable (trust
  comes from TPM quote, not the certificate). If issued by the trusted CA,
  the certificate MUST have Server Authentication EKU only.

- Push mode agents: No client certificates signed by the trusted CA.
  Authentication is via PoP bearer tokens only.

- Admins: Client certificates signed by the trusted CA with Client
  Authentication EKU.
"""

import logging
from typing import Any

from keylime.authorization.provider import Action, AuthorizationProvider, AuthorizationRequest, AuthorizationResponse

logger = logging.getLogger(__name__)


class SimpleAuthProvider(AuthorizationProvider):
    """Simple authorization provider implementing 4-category access control.

    This provider handles authorization for both verifier and registrar components.
    Actions are grouped into four categories:

    - PUBLIC: No authentication required (version info, evidence verification,
      agent self-registration in registrar)
    - AGENT_ONLY: Only agents can access, requires resource ownership
    - AGENT_OR_ADMIN: Agents with ownership OR admins (any resource)
    - ADMIN: Only admins can access (management operations in both components)

    Authorization logic:

    1. PUBLIC actions → Always allowed regardless of identity
    2. AGENT_ONLY actions → Requires identity_type == "agent" AND identity == resource
    3. AGENT_OR_ADMIN actions → Agent with ownership OR admin
    4. ADMIN actions (all others) → Requires identity_type == "admin"

    Note:
        This provider relies on the action handler to correctly set identity_type:

        - "admin": mTLS certificate present (extracted CN)
        - "agent": PoP bearer token present and valid (agent_id)
        - "anonymous": No authentication
    """

    # Actions that don't require authorization
    PUBLIC_ACTIONS = frozenset(
        {
            # Verifier public actions
            Action.READ_VERSION,
            Action.READ_SERVER_INFO,
            Action.VERIFY_IDENTITY,
            Action.VERIFY_EVIDENCE,
            Action.CREATE_SESSION,
            Action.EXTEND_SESSION,
            # Registrar public actions (agent self-registration)
            Action.REGISTER_AGENT,
            Action.ACTIVATE_AGENT,
        }
    )

    # Actions that ONLY agents can perform (on their own resources only)
    # Admins cannot access these - strict separation
    AGENT_ONLY_ACTIONS = frozenset(
        {
            Action.SUBMIT_ATTESTATION,
        }
    )

    # Actions that both agents and admins can perform
    # Agents: only for their own resources (identity == resource)
    # Admins: for any resource
    AGENT_OR_ADMIN_ACTIONS = frozenset(
        {
            Action.READ_AGENT,  # Agent can read own status, admin can read any
        }
    )

    # All other actions require ADMIN (mTLS certificate)

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize SimpleAuthProvider.

        Args:
            config: Not used by this provider (no configuration needed)
        """
        logger.info("Initialized SimpleAuthProvider")

    def authorize(self, request: AuthorizationRequest) -> AuthorizationResponse:
        """Make authorization decision based on identity type and resource ownership.

        Rules:
        1. PUBLIC actions → Always allowed
        2. AGENT_ONLY actions → Must have identity_type == "agent" AND identity == resource
        3. AGENT_OR_ADMIN actions → Agent with ownership OR admin
        4. ADMIN actions (all others) → Must have identity_type == "admin"

        Args:
            request: The authorization request

        Returns:
            AuthorizationResponse with decision and reason
        """
        # Rule 1: Public actions - always allowed
        if request.action in self.PUBLIC_ACTIONS:
            return AuthorizationResponse(
                allowed=True,
                reason=f"Public action: {request.action.value}",
            )

        # Rule 2: Agent-only actions - require agent identity and resource ownership
        # Admins cannot access these (strict separation for attestation submission)
        if request.action in self.AGENT_ONLY_ACTIONS:
            if request.identity_type != "agent":
                return AuthorizationResponse(
                    allowed=False,
                    reason=f"Action {request.action.value} requires agent authentication (PoP token)",
                )
            if request.identity != request.resource:
                return AuthorizationResponse(
                    allowed=False,
                    reason=f"Agent {request.identity} cannot access resource {request.resource} (ownership required)",
                )
            return AuthorizationResponse(
                allowed=True,
                reason=f"Agent {request.identity} accessing own resource",
            )

        # Rule 3: Agent-or-admin actions - agent with ownership OR admin
        if request.action in self.AGENT_OR_ADMIN_ACTIONS:
            if request.identity_type == "admin":
                return AuthorizationResponse(
                    allowed=True,
                    reason=f"Admin {request.identity} authorized for {request.action.value}",
                )
            if request.identity_type == "agent":
                if request.identity != request.resource:
                    return AuthorizationResponse(
                        allowed=False,
                        reason=f"Agent {request.identity} cannot access resource {request.resource} (ownership required)",
                    )
                return AuthorizationResponse(
                    allowed=True,
                    reason=f"Agent {request.identity} accessing own resource",
                )
            # Anonymous - denied
            return AuthorizationResponse(
                allowed=False,
                reason=f"Action {request.action.value} requires authentication",
            )

        # Rule 4: Admin actions (everything else) - require admin identity
        if request.identity_type != "admin":
            return AuthorizationResponse(
                allowed=False,
                reason=f"Action {request.action.value} requires admin authentication (mTLS certificate)",
            )
        return AuthorizationResponse(
            allowed=True,
            reason=f"Admin {request.identity} authorized for {request.action.value}",
        )

    def get_name(self) -> str:
        """Get provider name.

        Returns:
            Provider name for logging and debugging
        """
        return "simple"

    def health_check(self) -> bool:
        """Check provider health.

        The simple provider is always healthy (no external dependencies).

        Returns:
            Always returns True
        """
        return True
