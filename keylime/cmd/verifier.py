from keylime import cloud_verifier_tornado, config, keylime_logging
from keylime.common.migrations import apply

logger = keylime_logging.init_logging("verifier")


def main():
    # if we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option("verifier", "auto_migrate_db") and config.getboolean("verifier", "auto_migrate_db"):
        apply("cloud_verifier")

    cloud_verifier_tornado.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
