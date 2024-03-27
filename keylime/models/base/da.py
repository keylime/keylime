import sys

from keylime import config, keylime_logging
from keylime.da import record

logger = keylime_logging.init_logging("keylime_da")


class DAManager:
    def __init__(self) -> None:
        self._service = None
        self._backend = None

    def make_backend(self, service):
        self._service = service

        try:
            rmc = record.get_record_mgt_class(config.get(service, "durable_attestation_import", fallback=""))

            if rmc:
                self._backend = rmc("registrar")

        except record.RecordManagementException as rme:
            logger.error("Error initializing Durable Attestation: %s", rme)
            sys.exit(1)

    @property
    def service(self):
        return self._service

    @property
    def backend(self):
        return self._backend


# Create a global DAManager which can be referenced from any module
da_manager = DAManager()
