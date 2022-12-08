from logging import Logger
from typing import Optional


def retry_time(exponential: bool, base: float, ntries: int, logger: Optional[Logger]) -> float:
    if exponential:
        if base > 1:
            return base**ntries
        if logger:
            logger.warning("Base %f incompatible with exponential backoff", base)

    return abs(base)
