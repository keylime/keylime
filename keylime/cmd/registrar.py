import sys

import cryptography

from keylime import config, keylime_logging
from keylime.common.migrations import apply
from keylime.models import da_manager, db_manager
from keylime.web import RegistrarServer

logger = keylime_logging.init_logging("registrar")


def _check_devid_requirements() -> None:
    """Checks that the cryptography package is the version needed for DevID support (>= 38). Exits if this requirement
    is not met and DevID is the only identity allowable by the config.
    """
    tpm_identity = config.get("registrar", "tpm_identity", fallback="default")

    if int(cryptography.__version__.split(".", maxsplit=1)[0]) < 38:
        if tpm_identity == "iak_idevid":
            logger.error(
                "DevID is REQUIRED in config ('tpm_identity = %s') but python-cryptography version < 38", tpm_identity
            )
            sys.exit(1)

        if tpm_identity in ("default", "ek_cert_or_iak_idevid"):
            logger.info(
                "DevID is enabled in config ('tpm_identity = %s') but python-cryptography version < 38, so only the EK "
                "will be used for device registration",
                tpm_identity,
            )


def main() -> None:
    logger.info("Starting Keylime registrar...")

    config.check_version("registrar", logger=logger)

    # if we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option("registrar", "auto_migrate_db") and config.getboolean("registrar", "auto_migrate_db"):
        apply("registrar")

    # Check if DevID is required in config and, if so, that the required dependencies are met
    _check_devid_requirements()
    # Prepare to use the registrar database
    db_manager.make_engine("registrar")
    # Prepare backend for durable attestation, if configured
    da_manager.make_backend("registrar")

    # Start HTTP server
    server = RegistrarServer()
    server.start_multi()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
