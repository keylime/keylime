#!/usr/bin/python3

"""
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
"""
import sys

from keylime import keylime_logging
from keylime.da import attest

logger = keylime_logging.init_logging("attest")


def main() -> None:
    attest.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
        sys.exit(-1)
