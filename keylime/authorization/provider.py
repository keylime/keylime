"""Authorization provider interface for Keylime.

This module defines the abstract interface that all authorization providers
must implement. Authorization providers determine whether an authenticated
identity is authorized to perform a specific action on a resource.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class Action(Enum):
    """Actions that can be performed in Keylime.

    Each action represents a specific operation that requires authorization.
    Authorization providers use these actions to make access control decisions.
    """

    # Agent management actions
    CREATE_AGENT = "create_agent"
    READ_AGENT = "read_agent"
    UPDATE_AGENT = "update_agent"
    DELETE_AGENT = "delete_agent"
    LIST_AGENTS = "list_agents"
    REACTIVATE_AGENT = "reactivate_agent"
    STOP_AGENT = "stop_agent"

    # Attestation actions
    SUBMIT_ATTESTATION = "submit_attestation"
    READ_ATTESTATION = "read_attestation"
    LIST_ATTESTATIONS = "list_attestations"

    # Runtime policy management actions (IMA)
    CREATE_RUNTIME_POLICY = "create_runtime_policy"
    READ_RUNTIME_POLICY = "read_runtime_policy"
    UPDATE_RUNTIME_POLICY = "update_runtime_policy"
    DELETE_RUNTIME_POLICY = "delete_runtime_policy"
    LIST_RUNTIME_POLICIES = "list_runtime_policies"

    # Measured boot policy management actions (UEFI)
    CREATE_MB_POLICY = "create_mb_policy"
    READ_MB_POLICY = "read_mb_policy"
    UPDATE_MB_POLICY = "update_mb_policy"
    DELETE_MB_POLICY = "delete_mb_policy"
    LIST_MB_POLICIES = "list_mb_policies"

    # Session management actions
    CREATE_SESSION = "create_session"
    EXTEND_SESSION = "extend_session"

    # Evidence verification actions (public, for third-party integration)
    VERIFY_IDENTITY = "verify_identity"  # GET /verify/identity (proof of identity)
    VERIFY_EVIDENCE = "verify_evidence"  # POST /verify/evidence (one-shot attestation)

    # Registrar-specific actions (agent self-registration)
    # These are distinct from verifier agent management actions
    REGISTER_AGENT = "register_agent"  # Agent self-registers with TPM info (public)
    ACTIVATE_AGENT = "activate_agent"  # Agent completes TPM challenge-response (public)
    LIST_REGISTRATIONS = "list_registrations"  # Admin lists registered agents
    READ_REGISTRATION = "read_registration"  # Admin views registration details
    DELETE_REGISTRATION = "delete_registration"  # Admin deletes registration

    # Info/version endpoints (public)
    READ_VERSION = "read_version"
    READ_SERVER_INFO = "read_server_info"


@dataclass
class AuthorizationRequest:
    """Request for an authorization decision.

    Attributes:
        identity: The authenticated identity (e.g., CN from certificate, agent_id from token)
                  For anonymous requests, this is "anonymous"
        identity_type: Type of identity, one of:
                       - "admin": mTLS certificate present (CN extracted)
                       - "agent": PoP bearer token present and valid (agent_id)
                       - "anonymous": No authentication
        action: The action being requested
        resource: The resource being acted upon (e.g., agent_id, policy_name)
                  None for actions that don't target specific resources
    """

    identity: str
    identity_type: str  # "admin", "agent", "anonymous"
    action: Action
    resource: Optional[str] = None


@dataclass
class AuthorizationResponse:
    """Response from an authorization decision.

    Attributes:
        allowed: Whether the action is authorized
        reason: Human-readable reason for the decision (for logging and auditing)
    """

    allowed: bool
    reason: str


class AuthorizationProvider(ABC):
    """Abstract base class for authorization providers.

    Authorization providers implement the policy decision logic to determine
    whether an authenticated identity is authorized to perform an action.

    Providers must be stateless and thread-safe, as they may be called
    concurrently from multiple worker processes.

    Example implementation:

        class MyProvider(AuthorizationProvider):
            def __init__(self, config: dict) -> None:
                self._config = config

            def authorize(self, request: AuthorizationRequest) -> AuthorizationResponse:
                # Implement authorization logic
                if request.action == Action.READ_VERSION:
                    return AuthorizationResponse(allowed=True, reason="Public action")
                # ... more rules ...

            def get_name(self) -> str:
                return "my_provider"

            def health_check(self) -> bool:
                return True  # or check connectivity to external service
    """

    @abstractmethod
    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize the authorization provider.

        Args:
            config: Provider-specific configuration dictionary
                   Keys and values depend on the provider implementation
        """

    @abstractmethod
    def authorize(self, request: AuthorizationRequest) -> AuthorizationResponse:
        """Make an authorization decision.

        This method must be thread-safe and should not have side effects.

        Args:
            request: The authorization request containing identity, action, and resource

        Returns:
            AuthorizationResponse with decision (allowed/denied) and reason

        Raises:
            AuthorizationError: If the provider encounters an error making the decision
                               Callers should handle this by denying access (fail-safe)
        """

    @abstractmethod
    def get_name(self) -> str:
        """Get the provider name for logging and debugging.

        Returns:
            Provider name (e.g., "static_allowlist", "ldap", "opa")
        """

    @abstractmethod
    def health_check(self) -> bool:
        """Check if the provider is healthy and can make authorization decisions.

        This is called during provider initialization and can be used to verify
        connectivity to external services (e.g., LDAP server, OPA endpoint).

        Returns:
            True if healthy and ready to authorize requests, False otherwise
        """


class AuthorizationError(Exception):
    """Exception raised when an authorization provider encounters an error.

    This exception indicates that the provider was unable to make an
    authorization decision, not that the decision was "deny".

    Callers should handle this exception by denying access (fail-safe behavior)
    and logging the error for investigation.
    """
