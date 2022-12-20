from keylime import cloud_verifier_tornado, config, keylime_logging
from keylime.common.migrations import apply
from keylime.elchecking.policies import load_policies

logger = keylime_logging.init_logging("verifier")


def main() -> None:
    # if we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option("verifier", "auto_migrate_db") and config.getboolean("verifier", "auto_migrate_db"):
        apply("cloud_verifier")

    # Load explicitly the policy modules into Keylime for the verifier,
    # so that they are not loaded accidentally from other components
    load_policies()
    cloud_verifier_tornado.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
