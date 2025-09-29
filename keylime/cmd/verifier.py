from keylime import api_version, config, keylime_logging
from keylime.common.migrations import apply
from keylime.mba import mba

from keylime.web import VerifierServer
from keylime.models import da_manager, db_manager


logger = keylime_logging.init_logging("verifier")


def _log_startup_info() -> None:
    mode = config.get("verifier", "mode", fallback="pull")
    logger.info("Starting Keylime verifier in %s mode...", mode.upper())

    # Temporary warning when enabling push mode
    if mode == "push":
        logger.warning(
            "Push mode is experimental. Please report issues at "
            "https://github.com/keylime/keylime/issues/?q=label:push-mode"
        )

    # Log REST API versions supported by the verifier
    api_version.log_api_versions(logger)

    # Inform user when a new config file version is available
    config.check_version("verifier", logger=logger)


def main() -> None:
    _log_startup_info()

    # If we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option("verifier", "auto_migrate_db") and config.getboolean("verifier", "auto_migrate_db"):
        apply("cloud_verifier")

    # Explicitly load and initialize measured boot components
    mba.load_imports()

    # Prepare to use the cloud_verifier database
    db_manager.make_engine("cloud_verifier")
    # Prepare backend for durable attestation, if configured
    da_manager.make_backend("verifier")

    # Start HTTP server
    server = VerifierServer()
    server.start_multi()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
