import keylime.cmd.migrations_apply
from keylime import cloud_verifier_tornado, config, keylime_logging

logger = keylime_logging.init_logging("cloudverifier")


def main():
    # if we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option("cloud_verifier", "auto_migrate_db") and config.getboolean(
        "cloud_verifier", "auto_migrate_db"
    ):
        keylime.cmd.migrations_apply.apply("cloud_verifier")

    cloud_verifier_tornado.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
