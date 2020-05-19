#!/usr/bin/python3

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import sys

from keylime import registrar_common
from keylime import common
from keylime import keylime_logging

logger = keylime_logging.init_logging('registrar')

config = common.get_config()


def main(argv=sys.argv):
    registrar_common.start(config.getint(
        'registrar', 'registrar_tls_port'), config.getint('registrar', 'registrar_port'))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
