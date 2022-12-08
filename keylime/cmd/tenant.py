import sys

from keylime import keylime_logging, tenant

logger = keylime_logging.init_logging("tenant")


def main() -> None:
    try:
        tenant.main()
    except tenant.UserError as ue:
        logger.error(str(ue))
        sys.exit(1)
    except Exception as e:
        logger.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
