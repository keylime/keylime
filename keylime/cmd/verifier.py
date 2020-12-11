#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

from keylime import keylime_logging
from keylime import config
from keylime import cloud_verifier_tornado
import keylime.cmd.migrations_apply

logger = keylime_logging.init_logging('cloudverifier')


def main():
    # if we are configured to auto-migrate the DB, check if there are any migrations to perform
    if config.has_option('cloud_verifier', 'auto_migrate_db') and config.getboolean('cloud_verifier', 'auto_migrate_db'):
        keylime.cmd.migrations_apply.apply('cloud_verifier')

    cloud_verifier_tornado.main()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception(e)
