#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

from keylime import keylime_logging
from keylime import keylime_agent

logger = keylime_logging.init_logging('cloudagent')


def main():
    keylime_agent.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
