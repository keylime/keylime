"""Authorization manager for Keylime.

The authorization manager loads and manages authorization providers,
routing authorization requests to the configured provider.
"""

import logging
from typing import Any, Optional

from keylime import config
from keylime.authorization.provider import (
    AuthorizationError,
    AuthorizationProvider,
    AuthorizationRequest,
    AuthorizationResponse,
)
from keylime.authorization.providers.simple import SimpleAuthProvider

logger = logging.getLogger(__name__)

# Global authorization manager instance
_manager: Optional["AuthorizationManager"] = None


class AuthorizationManager:
    """Manages authorization providers and routes authorization requests.

    The manager is responsible for:
    - Loading the configured authorization provider
    - Routing authorization requests to the provider
    - Handling provider failures gracefully (fail-safe deny)
    - Logging all authorization decisions for audit trail
    """

    def __init__(self, component: str = "verifier") -> None:
        """Initialize the authorization manager.

        Args:
            component: The component name (e.g., "verifier", "registrar") used to
                      determine which configuration section to read from.

        Loads the configured provider from the Keylime configuration.
        If loading fails, uses a fail-safe deny-all provider.
        """
        self._provider: Optional[AuthorizationProvider] = None
        self._provider_name: str = ""
        self._component: str = component
        self._load_provider()

    def _load_provider(self) -> None:
        """Load the configured authorization provider from configuration."""
        try:
            # Get provider name from config (default: simple)
            provider_name = config.get(self._component, "authorization_provider", fallback="simple")

            logger.info("Loading authorization provider: %s", provider_name)

            # Load provider based on name
            if provider_name == "simple":
                self._load_simple_provider()
            else:
                logger.error("Unknown authorization provider: %s, falling back to simple", provider_name)
                self._load_simple_provider()

            if self._provider:
                # Verify provider is healthy
                if not self._provider.health_check():
                    logger.warning("Authorization provider %s is unhealthy", provider_name)

                logger.info("Authorization provider %s loaded successfully", self._provider.get_name())

        except Exception as e:
            logger.error("Failed to load authorization provider: %s", e)
            logger.error("SECURITY: Falling back to deny-all provider for safety")
            self._load_deny_all_provider()

    def _load_simple_provider(self) -> None:
        """Load the simple authorization provider.

        This is the default provider that implements a 4-category policy:
        - PUBLIC: No authentication required
        - AGENT_ONLY: PoP token + resource ownership (agents only)
        - AGENT_OR_ADMIN: PoP token or mTLS certificate
        - ADMIN: mTLS certificate only
        """
        self._provider = SimpleAuthProvider({})
        self._provider_name = "simple"

    def _load_deny_all_provider(self) -> None:
        """Load a fail-safe deny-all provider.

        This provider denies all requests and is used as a fallback
        when the configured provider fails to load.
        """

        class DenyAllProvider(AuthorizationProvider):
            """Fail-safe provider that denies all authorization requests."""

            def __init__(self, provider_config: dict[str, Any]) -> None:
                pass

            def authorize(self, request: AuthorizationRequest) -> AuthorizationResponse:
                return AuthorizationResponse(
                    allowed=False,
                    reason="Authorization provider failed to load - denying all requests for security",
                )

            def get_name(self) -> str:
                return "deny_all"

            def health_check(self) -> bool:
                return False

        self._provider = DenyAllProvider({})
        self._provider_name = "deny_all"

    def authorize(self, request: AuthorizationRequest) -> AuthorizationResponse:
        """Make an authorization decision.

        Routes the request to the configured provider and logs the decision.

        Args:
            request: The authorization request

        Returns:
            AuthorizationResponse with decision

        Raises:
            AuthorizationError: If provider is not loaded
        """
        if not self._provider:
            raise AuthorizationError("Authorization provider not loaded")

        try:
            response = self._provider.authorize(request)

            # Log authorization decision
            log_msg = "Authorization %s: identity=%s, identity_type=%s, action=%s, resource=%s, reason=%s"
            log_args = (
                "GRANTED" if response.allowed else "DENIED",
                request.identity,
                request.identity_type,
                request.action.value,
                request.resource,
                response.reason,
            )

            if response.allowed:
                logger.info(log_msg, *log_args)
            else:
                logger.warning(log_msg, *log_args)

            return response

        except Exception as e:
            logger.error(
                "Authorization provider %s encountered error: %s (denying by default)",
                self._provider_name,
                e,
                exc_info=True,
            )
            # Fail-safe: deny on error
            return AuthorizationResponse(
                allowed=False,
                reason=f"Authorization provider error: {e}",
            )

    def get_provider_name(self) -> str:
        """Get the name of the loaded provider.

        Returns:
            Provider name (e.g., "static_allowlist", "deny_all")
        """
        return self._provider_name if self._provider else "none"


def get_authorization_manager(component: str = "verifier") -> AuthorizationManager:
    """Get the global authorization manager instance.

    Args:
        component: The component name (e.g., "verifier", "registrar").
                  Used to determine which configuration section to read from.

    Returns:
        AuthorizationManager singleton instance

    Note:
        The manager is created on first access and reused for all
        subsequent calls. Since each component (verifier, registrar)
        runs in a separate process, the component parameter is used
        only on first initialization.
    """
    global _manager

    if _manager is None:
        _manager = AuthorizationManager(component)

    return _manager
