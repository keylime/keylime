import logging
from logging import Logger
from logging import config as logging_config
from typing import Any, Callable, Dict

from keylime import config

logging_config.fileConfig(config.get_config("logging"))


def set_log_func(loglevel: int, logger: Logger) -> Callable[..., None]:
    log_func = logger.info

    if loglevel == logging.CRITICAL:
        log_func = logger.critical
    elif loglevel == logging.ERROR:
        log_func = logger.error
    elif loglevel == logging.WARNING:
        log_func = logger.warning
    elif loglevel == logging.INFO:
        log_func = logger.info
    elif loglevel == logging.DEBUG:
        log_func = logger.debug

    return log_func


def log_http_response(logger: Logger, loglevel: int, response_body: Dict[str, Any]) -> bool:
    """Takes JSON response payload and logs error info"""
    if None in [response_body, logger]:
        return False

    log_func = set_log_func(loglevel, logger)

    matches = ["results", "code", "status"]
    if all(x in response_body for x in matches):
        log_func(f"Response code {response_body['code']}: {response_body['status']}")
    else:
        logger.error("Error: unexpected or malformed http response payload")
        return False

    return True


def init_logging(loggername: str) -> Logger:
    logger = logging.getLogger(f"keylime.{loggername}")
    logging.getLogger("requests").setLevel(logging.WARNING)

    return logger
