#!/usr/bin/env python

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import asyncio

from keylime import common
import keylime.keylime_logging as keylime_logging

try:
    import simplejson as json
except ImportError:
    raise("Simplejson is mandatory, please install")

config = common.get_config()

logger = keylime_logging.init_logging('print_metadata')


async def execute(revocation):
    print(json.loads(revocation['meta_data']))
