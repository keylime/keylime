"""Monitor PUSH mode agents for timeout detection.

This module implements event-driven timeout detection for PUSH mode agents.
Instead of polling the database continuously, it schedules individual timeout
callbacks when attestations are received. When an agent exceeds the timeout
threshold, its accept_attestations flag is set to False, which causes
attestation_status to show as "FAIL".

Integration points:
- Call schedule_agent_timeout(agent_id) when a PUSH mode attestation is received
- Call cancel_agent_timeout(agent_id) when a PUSH mode agent is deleted

This approach eliminates continuous database polling, significantly reducing load.
"""

import threading
import time
from typing import Dict, Optional

import tornado.ioloop
from sqlalchemy import and_, or_

from keylime import config, keylime_logging
from keylime.db.verifier_db import VerfierMain

logger = keylime_logging.init_logging("push_agent_monitor")

# Timeout multiplier for quote_interval
# We wait 2x the quote_interval before marking an agent as failed
# This allows for network delays and processing time
_TIMEOUT_MULTIPLIER = 2.0

# In-memory map of agent_id -> timeout handle for active timeouts
# This allows us to cancel/reschedule timeouts without database queries
# Access to this dictionary must be protected by _agent_timeout_handles_lock
_agent_timeout_handles: Dict[str, object] = {}
_agent_timeout_handles_lock = threading.Lock()


def get_maximum_attestation_interval(quote_interval: float) -> float:
    """Calculate the maximum attestation interval (timeout threshold).

    Args:
        quote_interval: The configured quote interval in seconds

    Returns:
        The maximum attestation interval (quote_interval * multiplier)
    """
    return quote_interval * _TIMEOUT_MULTIPLIER


def _mark_agent_failed(agent_id: str, expected_handle: object) -> None:
    """Mark a specific agent as failed due to timeout.

    This is called when a scheduled timeout fires, indicating the agent
    has not sent an attestation within the expected timeframe.

    Args:
        agent_id: The agent ID to mark as failed
        expected_handle: The timeout handle that was scheduled (used to verify
                        this callback hasn't been superseded by a newer timeout)
    """
    try:
        # Verify active timeout for this agent
        # This prevents a race where:
        # 1. Old timeout H1 is scheduled
        # 2. New attestation arrives, cancels H1, schedules new timeout H2
        # 3. H1 was already queued and executes anyway
        # 4. H1 would incorrectly remove H2 from the dictionary
        with _agent_timeout_handles_lock:
            current_handle = _agent_timeout_handles.get(agent_id)
            if current_handle != expected_handle:
                # Handle cancelled/superseded by a newer timeout, exit without database modification
                return

            # Still active timeout, remove it from the map
            _agent_timeout_handles.pop(agent_id, None)

        # Import here to avoid circular dependency issues
        # pylint: disable=import-outside-toplevel
        from keylime.cloud_verifier_tornado import session_context

        # Update database to mark agent as failed using singleton session context
        with session_context() as session:
            agent = session.query(VerfierMain).filter_by(agent_id=agent_id).first()

            if agent is None:
                logger.warning("Agent %s not found in database during timeout handling", agent_id)
                return

            # Only update if currently accepting attestations
            if agent.accept_attestations is True:  # pyright: ignore[reportGeneralTypeIssues]
                quote_interval = config.getfloat("verifier", "quote_interval", fallback=2.0)
                timeout_seconds = quote_interval * _TIMEOUT_MULTIPLIER

                logger.warning(
                    "Agent %s has timed out (no attestation received within %.1f seconds). "
                    "Setting accept_attestations to False.",
                    agent_id,
                    timeout_seconds,
                )
                agent.accept_attestations = False  # pyright: ignore[reportAttributeAccessIssue]
            else:
                logger.debug("Agent %s timeout fired but already marked as failed", agent_id)

    except Exception as e:
        logger.error("Error marking agent %s as failed: %s", agent_id, e)
        logger.exception(e)


def schedule_agent_timeout(agent_id: str, timeout_seconds: Optional[float] = None) -> None:
    """Schedule a timeout for a specific PUSH mode agent.

    This should be called whenever an attestation is received from a PUSH mode agent.
    If a timeout is already scheduled for this agent, it will be cancelled and
    rescheduled.

    Args:
        agent_id: The agent ID to schedule timeout for
        timeout_seconds: Custom timeout in seconds (defaults to quote_interval * _TIMEOUT_MULTIPLIER)
    """
    try:
        # Cancel any existing timeout for this agent
        cancel_agent_timeout(agent_id)

        # Calculate timeout if not provided
        if timeout_seconds is None:
            quote_interval = config.getfloat("verifier", "quote_interval", fallback=2.0)
            timeout_seconds = quote_interval * _TIMEOUT_MULTIPLIER

        # Schedule the timeout callback
        # Pass the timeout_handle to the callback so it can verify it's still active
        # The lambda captures timeout_handle by reference, which will be assigned before the callback executes
        io_loop = tornado.ioloop.IOLoop.current()
        timeout_handle = io_loop.call_later(timeout_seconds, lambda: _mark_agent_failed(agent_id, timeout_handle))

        # Store the handle so we can cancel it later if needed
        # Protect dictionary access with lock
        with _agent_timeout_handles_lock:
            _agent_timeout_handles[agent_id] = timeout_handle

        logger.debug(
            "Scheduled timeout for agent %s (will fire in %.1f seconds if no attestation received)",
            agent_id,
            timeout_seconds,
        )

    except Exception as e:
        logger.error("Error scheduling timeout for agent %s: %s", agent_id, e)
        logger.exception(e)


def cancel_agent_timeout(agent_id: str) -> None:
    """Cancel a scheduled timeout for a specific agent.

    This should be called when an agent is deleted or when rescheduling a timeout.

    Args:
        agent_id: The agent ID to cancel timeout for
    """
    # Protect dictionary access with lock
    with _agent_timeout_handles_lock:
        timeout_handle = _agent_timeout_handles.pop(agent_id, None)

    if timeout_handle is not None:
        try:
            io_loop = tornado.ioloop.IOLoop.current()
            io_loop.remove_timeout(timeout_handle)
            logger.debug("Cancelled timeout for agent %s", agent_id)
        except Exception as e:
            logger.error("Error cancelling timeout for agent %s: %s", agent_id, e)


def check_push_agent_timeouts() -> None:
    """Check all PUSH mode agents for timeouts and mark failed ones.

    This function:
    1. Queries all PUSH mode agents using is_push_mode_agent() logic:
       - operational_state IS NULL (never polled), OR
       - ip IS NULL AND port IS NULL (cannot be contacted)
    2. Checks if last_received_quote timestamp is older than timeout threshold
    3. Sets accept_attestations = False for agents that have timed out

    The timeout threshold is calculated as: quote_interval * _TIMEOUT_MULTIPLIER
    """
    try:
        # Get quote interval from config
        quote_interval = config.getfloat("verifier", "quote_interval", fallback=2.0)
        timeout_seconds = quote_interval * _TIMEOUT_MULTIPLIER
        current_time = int(time.time())

        # Import here to avoid circular dependency issues
        # pylint: disable=import-outside-toplevel
        from keylime.cloud_verifier_tornado import session_context

        # Use singleton session context to avoid engine leaks
        with session_context() as session:
            # Query all PUSH mode agents using the same logic as is_push_mode_agent():
            # 1. operational_state IS NULL (never polled), OR
            # 2. ip IS NULL AND port IS NULL (cannot be contacted/polled)
            push_agents = (
                session.query(VerfierMain)
                .filter(
                    or_(
                        VerfierMain.operational_state.is_(None),  # type: ignore[no-untyped-call]
                        and_(
                            VerfierMain.ip.is_(None),  # type: ignore[no-untyped-call]
                            VerfierMain.port.is_(None),  # type: ignore[no-untyped-call]
                        ),
                    )
                )
                .all()
            )

            if not push_agents:
                logger.debug("No PUSH mode agents found for timeout check")
                return

            logger.debug(
                "Checking %d PUSH mode agent(s) for timeouts (threshold: %.1f seconds)",
                len(push_agents),
                timeout_seconds,
            )

            timed_out_count = 0
            for agent in push_agents:
                # Skip agents that have never received an attestation
                if agent.last_received_quote is None:
                    logger.debug("Agent %s has never received an attestation, skipping timeout check", agent.agent_id)
                    continue

                # Calculate time since last attestation
                time_since_last = current_time - agent.last_received_quote

                # Check if agent has timed out
                if time_since_last > timeout_seconds:  # pyright: ignore[reportGeneralTypeIssues]
                    # Only update if currently accepting attestations
                    # This prevents excessive logging for already-failed agents
                    if agent.accept_attestations is True:  # pyright: ignore[reportGeneralTypeIssues]
                        logger.warning(
                            "Agent %s has timed out (%.1f seconds since last attestation, threshold: %.1f seconds). "
                            "Setting accept_attestations to False.",
                            agent.agent_id,
                            time_since_last,
                            timeout_seconds,
                        )
                        agent.accept_attestations = False  # pyright: ignore[reportAttributeAccessIssue]
                        timed_out_count += 1
                    else:
                        logger.debug(
                            "Agent %s already marked as failed (%.1f seconds since last attestation)",
                            agent.agent_id,
                            time_since_last,
                        )
                else:
                    logger.debug(
                        "Agent %s is healthy (%.1f seconds since last attestation, threshold: %.1f seconds)",
                        agent.agent_id,
                        time_since_last,
                        timeout_seconds,
                    )

            if timed_out_count > 0:
                logger.debug("Marked %d PUSH mode agent(s) as failed due to timeout", timed_out_count)

    except Exception as e:
        logger.error("Error checking PUSH mode agent timeouts: %s", e)
        logger.exception(e)
