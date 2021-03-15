'''
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2021 IBM Corp.
'''

import json
import sys
import argparse
import traceback

from keylime import config
from keylime import keylime_logging

logger = keylime_logging.init_logging('measured_boot')

def read_mb_refstate(mb_path=None):
    if mb_path is None:
        mb_path = config.get('tenant', 'mb_refstate')

    mb_data = None
    # Purposefully die if path doesn't exist
    with open(mb_path, 'r') as f:
        mb_data = json.load(f)

    logger.debug("Loaded measured boot reference state from %s", mb_path)

    return mb_data

def process_refstate(mb_refstate_data=None) :
    if isinstance(mb_refstate_data, dict) :
        return mb_refstate_data
    return mb_refstate_data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', default="mbtest.txt")
    args = parser.parse_args()
    try:
        read_mb_refstate(args.infile)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
