"""Validators module."""
import re


def valid_regex(regex):
    """Check if string is a valid regular expression."""
    if regex is None:
        return True, None, None

    try:
        compiled_regex = re.compile(regex)
    except re.error as regex_err:
        err = "Invalid regex: " + regex_err.msg + "."
        return False, None, err

    return True, compiled_regex, None


def valid_exclude_list(exclude_list):
    """Check if the list is composed of valid regex."""
    if not exclude_list:
        return True, None, None

    combined_regex = "(" + ")|(".join(exclude_list) + ")"
    return valid_regex(combined_regex)


def valid_hex(value):
    """Check if the string is a valid hex number representation."""
    try:
        int(value, 16)
    except Exception:
        return False
    return True


def valid_uuid(uuid: str) -> bool:
    """Check if the string is a valid UUID."""
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


def valid_agent_id(agent_id: str) -> bool:
    """Check if agent_id is valid."""
    valid = False
    try:
        valid = bool(re.fullmatch(r"[\w.-]+", agent_id))
    except Exception:
        pass
    return valid
