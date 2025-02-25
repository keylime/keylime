from keylime import api_version as keylime_api_version
from keylime import keylime_logging
from keylime.web.base import Controller

logger = keylime_logging.init_logging("registrar")


class VersionController(Controller):
    # GET /version
    def version(self, **_params):
        version_info = {
            "current_version": keylime_api_version.current_version(),
            "supported_versions": keylime_api_version.all_versions(),
        }
        self.respond(200, "Success", version_info)
