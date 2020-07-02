'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import uuid

from keylime import common
from keylime import keylime_logging
from keylime import tornado_requests

logger = keylime_logging.init_logging('openstack')


def get_openstack_uuid(uuid_service_ip='169.254.169.254',
                       uuid_service_resource='/openstack/2012-08-10/meta_data.json'):

    logger.debug("Getting instance UUID from openstack http://%s%s"%(uuid_service_ip,uuid_service_resource))
    try:
        response = tornado_requests.request("GET", "http://" + uuid_service_ip + uuid_service_resource)
        if response.status_code == 200:
            response_body = response.yaml()
            return response_body["uuid"]
        logger.debug("Forcing using locally generated uuid.")
        return str(uuid.uuid4())
    except Exception:
        logger.debug("Using locally generated uuid.  Error getting UUID from openstack: %s\n"%(e))
        return str(uuid.uuid4())
