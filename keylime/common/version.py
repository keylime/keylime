import re
from typing import Tuple, Union


def str_to_version(v_str: str) -> Union[Tuple[int, int], None]:
    """
    Validates the string format and converts the provided string to a tuple of
    ints which can be sorted and compared.

    :returns: Tuple with version number parts converted to int. In case of
    invalid version string, returns None
    """

    # Strip to remove eventual quotes and spaces
    v_str = v_str.strip('" ')

    m = re.match(r"^(\d+)\.(\d+)$", v_str)

    if not m:
        return None

    return (int(m.group(1)), int(m.group(2)))
