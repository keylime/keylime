#!/usr/bin/env python

'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2017 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
'''

import time
import os
import configparser

import keylime.tornado_requests as tornado_requests
import keylime.ca_util as ca_util
import keylime.secure_mount as secure_mount
import keylime.common as common
import keylime.keylime_logging as keylime_logging

# read the config file
config = configparser.RawConfigParser()
config.read(common.CONFIG_FILE)

logger = keylime_logging.init_logging('update_crl')

async def execute(json_revocation):
    if json_revocation['type']!='revocation':
        return

    secdir = secure_mount.mount()

    cert_path = config.get('cloud_agent','revocation_cert')
    if cert_path == "default":
        cert_path = f'{secdir}/unzipped/RevocationNotifier-cert.crt'
    else:
        # if it is a relative, convert to absolute in work_dir
        if cert_path[0]!='/':
            cert_path = os.path.abspath(f'{common.WORK_DIR}/{cert_path}')
        if not os.path.exists(cert_path):
            raise Exception(f"revocation_cert {os.path.abspath(cert_path)} not found")

    # get the updated CRL
    dist_path = ca_util.get_crl_distpoint(cert_path)

    with open(f"{secdir}/unzipped/cacrl.der", "rb") as f:
        oldcrl = f.read()

    updated = False
    for i in range(10):
        logger.debug(f"Getting updated CRL from {dist_path}")        res = tornado_requests.request("GET", dist_path, None, None, None)
        response = await res
        if response.status_code !=200:
            logger.warn(f"Unable to get updated CRL from {dist_path}.  Code {response.status_code}")
            time.sleep(1)
            continue
        if response.body == oldcrl:
            logger.warn("CRL not yet updated, trying again in 1 second...")
            time.sleep(1)
            continue

        # write out the updated CRL
        logger.debug(f"Updating CRL in {secdir}/unzipped/cacrl.der")
        with open(f"{secdir}/unzipped/cacrl.der", "w") as f:
            f.write(response.body)
        ca_util.convert_crl_to_pem(f"{secdir}/unzipped/cacrl.der", f"{secdir}/unzipped/cacrl.pem")

        updated = True
        break

    if not updated:
        logger.error(f"Unable to load new CRL from {dist_path} after receiving notice of a revocation")