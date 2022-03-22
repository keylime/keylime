#!/usr/bin/python3

'''
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Massachusetts Institute of Technology.
'''

import sys

from keylime import keylime_logging
from keylime import tenant

logger = keylime_logging.init_logging('tenant')


def main():
    try:
        tenant.main()
    except tenant.UserError as ue:
        logger.error(str(ue))
        sys.exit(1)
    except Exception as e:
        logger.exception(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
