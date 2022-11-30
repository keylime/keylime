def adjust(config, mapping) -> None:  # pylint: disable=unused-argument
    """
    Set the test_adjust option
    """

    print("Adjusting configuration")

    for component in config:
        if "test_adjust" in config[component]:
            print("Setting test_adjust")
            config[component]["test_adjust"] = "adjusted 3.0"
