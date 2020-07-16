#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

from keylime import keylime_logging
from keylime import tenant

logger = keylime_logging.init_logging('tenant')


def main():
    tenant.main()


if __name__ == "__main__":
    try:
        main()
    except tenant.UserError as ue:
        logger.error(str(ue))
    except Exception as e:
        logger.exception(e)
