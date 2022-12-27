import asyncio
import os
import time
from typing import Dict

from keylime import ca_util
from keylime import config as common
from keylime import keylime_logging, secure_mount, tornado_requests

logger = keylime_logging.init_logging("update_crl")


def execute(json_revocation: Dict[str, str]) -> None:
    if json_revocation["type"] != "revocation":
        return

    secdir = secure_mount.mount()

    cert_path = common.get("agent", "revocation_cert")
    if cert_path == "default":
        cert_path = os.path.join(secdir, "unzipped", "RevocationNotifier-cert.crt")
    else:
        # if it is a relative, convert to absolute in work_dir
        if cert_path[0] != "/":
            cert_path = os.path.abspath(os.path.join(common.WORK_DIR, cert_path))
        if not os.path.exists(cert_path):
            raise Exception(f"revocation_cert {os.path.abspath(cert_path)} not found")

    # get the updated CRL
    dist_path = ca_util.get_crl_distpoint(cert_path)

    with open(os.path.join(secdir, "unzipped", "cacrl.der"), "rb") as f:
        oldcrl = f.read()

    updated = False
    for _ in range(10):
        logger.debug("Getting updated CRL from %s", dist_path)
        response = asyncio.get_event_loop().run_until_complete(
            tornado_requests.request("GET", dist_path, None, None, None)  # type: ignore
        )
        if response.status_code != 200:
            logger.warning("Unable to get updated CRL from %s.  Code %d", dist_path, response.status_code)
            time.sleep(1)
            continue
        if response.body == oldcrl:
            logger.warning("CRL not yet updated, trying again in 1 second...")
            time.sleep(1)
            continue

        # write out the updated CRL
        logger.debug("Updating CRL in %s/unzipped/cacrl.der", secdir)
        with open(os.path.join(secdir, "unzipped", "cacrl.der"), "wb") as f:
            assert not isinstance(response.body, str)
            f.write(response.body)
        ca_util.convert_crl_to_pem(
            os.path.join(secdir, "unzipped", "cacrl.der"), os.path.join(secdir, "unzipped", "cacrl.pem")
        )
        updated = True
        break

    if not updated:
        logger.error("Unable to load new CRL from %s after receiving notice of a revocation", dist_path)
