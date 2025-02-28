"""
Module to assist with logging in the policy tool.

SPDX-License-Identifier: Apache-2.0
Copyright 2024 Red Hat, Inc.
"""

import logging
import sys
from typing import Optional, TextIO

_policy_logger: Optional[logging.Logger] = None
_log_stream: TextIO = sys.stderr
_log_handler: logging.Handler = logging.Handler()
_log_handler_verbose: logging.Handler = logging.Handler()


class Logger:
    """A helper class to handle logging."""

    POLICY_LOGGER_FORMAT = r"%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s"
    POLICY_LOGGER_DATEFMT = r"%Y-%m-%d %H:%M:%S"

    _logger: logging.Logger
    _formatter: logging.Formatter = logging.Formatter(fmt=POLICY_LOGGER_FORMAT, datefmt=POLICY_LOGGER_DATEFMT)
    _verbose: bool = False

    def __init__(self, verbose: bool = False):
        """Initialize the class with the specified verbosity and stream."""
        global _policy_logger

        if _policy_logger is None:
            _policy_logger = logging.getLogger("keylime-policy")
            # We stop log propagation to prevent both duplication and
            # to avoid the possibility of other loggers writing to
            # stdout, which would mix logs with the relevant data the
            # tool might output.
            _policy_logger.propagate = False

        self._logger = _policy_logger

        self._verbose = verbose
        self.setStream(_log_stream)

    def setStream(self, stream: TextIO) -> None:
        """Define the stream for the logger."""
        # As some functionality may output data to stdout, let us log
        # everything to stderr by default (default stream), so that it
        # won't interfere with the relevant data.
        global _log_stream
        global _log_handler
        global _log_handler_verbose

        _log_stream = stream
        _log_handler = logging.StreamHandler(_log_stream)
        _log_handler.setLevel(logging.INFO)
        _log_handler_verbose = logging.StreamHandler(_log_stream)
        _log_handler_verbose.setLevel(logging.DEBUG)

        # For the DEBUG level, we also have a formatter, with extra
        # info, such as the timestamp.
        _log_handler_verbose.setFormatter(self._formatter)

        if self._verbose:
            self.enableVerbose()
        else:
            self.disableVerbose()

    def enableVerbose(self) -> None:
        """Use a verbose logger."""
        self._logger.handlers = [_log_handler_verbose]
        self._logger.setLevel(logging.DEBUG)

    def disableVerbose(self) -> None:
        """Do not use a verbose logger."""
        self._logger.handlers = [_log_handler]
        self._logger.setLevel(logging.INFO)

    def logger(self) -> logging.Logger:
        """Return the logger."""
        return self._logger
