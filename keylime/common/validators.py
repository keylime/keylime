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
