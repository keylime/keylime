#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

from keylime import ca_util
from keylime import keylime_logging

logger = keylime_logging.init_logging('ca-util')


def main():
    ca_util.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
