"""Shutdown coordination for graceful server termination.

Provides a process-wide shutdown flag that attestation loops and retry
schedulers check before starting new work.  Setting the flag prevents
new IOLoop callbacks from being scheduled and allows in-flight
operations to drain before the event loop stops.
"""

import asyncio

_shutdown_event = asyncio.Event()


def request_shutdown() -> None:
    """Signal that the process is shutting down."""
    _shutdown_event.set()


def is_shutting_down() -> bool:
    """Return True if shutdown has been requested."""
    return _shutdown_event.is_set()
