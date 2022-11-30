from typing import NoReturn


# This adjust method raises exception.
# The exception should be raised
def adjust(config, mapping) -> NoReturn:  # pylint: disable=unused-argument
    """
    Raise exception
    """
    print("Adjusting configuration")
    raise Exception("Testing exception on adjust")
