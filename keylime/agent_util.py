"""Agent utility functions.

This module provides utility functions for working with agents,
including determining agent mode (PUSH vs PULL) and other agent-related helpers.
"""

from keylime.db.verifier_db import VerfierMain


def is_push_mode_agent(agent: VerfierMain) -> bool:
    """Determine if an agent is operating in PUSH mode.

    PUSH mode agents are identified by:
    1. operational_state is None (never been polled), OR
    2. Both ip and port are None (cannot be contacted/polled)

    Args:
        agent: The VerfierMain database object to check

    Returns:
        True if the agent is in PUSH mode, False otherwise
    """
    # Check if operational_state is None (pure PUSH mode, never polled)
    if agent.operational_state is None:
        return True

    # Check if both ip and port are None (PUSH mode agent that may have state)
    if agent.ip is None and agent.port is None:
        return True

    # Otherwise, it's a PULL mode agent
    return False
