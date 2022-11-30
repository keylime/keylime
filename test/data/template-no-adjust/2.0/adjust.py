# This adjust script does not have the adjust() method.
# Loading this from convert_config should raise exception
def something(config, mapping) -> None:  # pylint: disable=unused-argument
    return
