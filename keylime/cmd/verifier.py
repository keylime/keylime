#!/usr/bin/python3

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

from keylime import keylime_logging
from keylime import cloud_verifier_tornado

logger = keylime_logging.init_logging('cloudverifier')


def main():
    cloud_verifier_tornado.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
