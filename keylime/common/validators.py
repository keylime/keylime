"""Validators module."""

import re
from typing import List, Optional, Pattern, Tuple


def valid_regex(regex: Optional[str]) -> Tuple[Optional[Pattern[str]], Optional[str]]:
    """Check if string is a valid regular expression."""
    if regex is None:
        return None, None

    try:
        compiled_regex = re.compile(regex)
    except re.error as regex_err:
        err = "Invalid regex: " + regex_err.msg + "."
        return None, err

    return compiled_regex, None


def valid_exclude_list(exclude_list: Optional[List[str]]) -> Tuple[Optional[Pattern[str]], Optional[str]]:
    """Check if the list is composed of valid regex."""
    if not exclude_list:
        return None, None

    combined_regex = "(" + ")|(".join(exclude_list) + ")"
    return valid_regex(combined_regex)


def valid_hex(value: Optional[str]) -> bool:
    """Check if the string is a valid hex number representation."""
    if value is None:
        return False
    try:
        int(value, 16)
    except Exception:
        return False
    return True


def valid_uuid(uuid: Optional[str]) -> bool:
    """Check if the string is a valid UUID."""
    if not uuid:
        return False
    valid = False
    try:
        valid = bool(
            re.fullmatch(
                r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
                uuid,
                re.I,
            )
        )
    except Exception:
        pass
    return valid


def valid_agent_id(agent_id: Optional[str]) -> bool:
    """Check if agent_id is valid."""
    if not agent_id:
        return False
    valid = False
    try:
        valid = bool(re.fullmatch(r"[\w.-]+", agent_id))
    except Exception:
        pass
    return valid
