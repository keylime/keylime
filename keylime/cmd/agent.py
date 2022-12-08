from keylime import keylime_agent, keylime_logging

logger = keylime_logging.init_logging("cloudagent")


def main() -> None:
    keylime_agent.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
