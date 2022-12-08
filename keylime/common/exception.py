from typing import Any, Dict, Optional


class KeylimeException(Exception):
    """Base class for all Keylime exceptions"""

    _msg_fmt = "An unknown exception occurred."

    def __init__(self, message: Optional[str] = None, **kwargs: Dict[str, Any]):
        if not message:
            message = self._msg_fmt % kwargs

        super().__init__(message)


class InvalidAgentState(KeylimeException):
    _msg_fmt = "Invalid agent state."
