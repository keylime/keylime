from keylime import ca_util, keylime_logging

logger = keylime_logging.init_logging("ca-util")


def main() -> None:
    ca_util.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
