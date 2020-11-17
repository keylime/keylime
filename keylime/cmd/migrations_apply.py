#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2020 Michael Peters (mpeters@redhat.com), Red Hat, Inc.
'''

import alembic.config
import os
from keylime import keylime_logging


def main():
    apply(None)


def apply(db_name):
    here = os.path.dirname(os.path.abspath(__file__))

    # the config file for alembic is in the migrations directory
    alembic_args = ['-c', os.path.join(here, '..', 'migrations', 'alembic.ini')]

    # if we are restricting it to a single db, add that to the custom args (-x)
    if db_name:
        alembic_args.extend(['-x', 'db=' + db_name])

    alembic_args.extend(['upgrade', 'head'])

    alembic.config.main(argv=alembic_args)


if __name__ == "__main__":
    logger = keylime_logging.init_logging('migrations')
    try:
        main()
    except Exception as e:
        logger.exception(e)
