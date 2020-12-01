#!/usr/bin/env python

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import simplejson as json

from keylime import common
import keylime.keylime_logging as keylime_logging


config = common.get_config()

logger = keylime_logging.init_logging('print_metadata')


async def execute(revocation):
    print(json.loads(revocation['meta_data']))
