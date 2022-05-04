#!/usr/bin/env python

"""
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
"""

from keylime import json, keylime_logging

logger = keylime_logging.init_logging("print_metadata")


async def execute(revocation):
    print(json.loads(revocation["meta_data"]))
