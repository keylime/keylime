#!/usr/bin/python3

'''
SPDX-License-Identifier: BSD-2-Clause
Copyright 2017 Massachusetts Institute of Technology.
'''

import sys

from keylime import common
from keylime import keylime_logging
from keylime import registrar_common

logger = keylime_logging.init_logging('provider-registrar')
config = common.get_config()


def main(argv=sys.argv):
    registrar_common.start(config.getint('registrar', 'provider_registrar_tls_port'),config.getint('registrar', 'provider_registrar_port'),config.get('registrar','prov_db_filename'))

if __name__=="__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
