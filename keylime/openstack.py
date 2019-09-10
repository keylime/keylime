'''
DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Assistant Secretary of Defense for
Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or
FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this
material are those of the author(s) and do not necessarily reflect the views of the
Assistant Secretary of Defense for Research and Engineering.

Copyright 2015 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the US Government with Unlimited Rights, as defined in DFARS Part
252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government
rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed
above. Use of this work other than as specifically authorized by the U.S. Government may
violate any copyrights that exist in this work.
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
