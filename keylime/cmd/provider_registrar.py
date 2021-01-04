#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

from keylime import config
from keylime import keylime_logging
from keylime import registrar_common

logger = keylime_logging.init_logging('provider-registrar')


def main():
    registrar_common.start(
        config.get('registrar', 'provider_registrar_ip'),
        config.getint('registrar', 'provider_registrar_tls_port'),
        config.getint('registrar', 'provider_registrar_port'))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
